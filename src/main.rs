//! Post-Quantum File Encryption Tool
//!
//! Provides hybrid post-quantum encryption using ML-KEM-1024 (NIST FIPS 203)
//! for key encapsulation, X25519 for an additional DH secret, and AES-256-GCM
//! for symmetric encryption. The AES key is HKDF-derived from the concatenation
//! of the ML-KEM shared secret and the X25519 shared secret (with a salt).
//!
//! # Security Features
//! - ML-KEM-1024: Post-quantum secure key encapsulation mechanism
//! - X25519: Ephemeral-static Diffie-Hellman mixed with the KEM secret
//! - HKDF-SHA256: Derives the AES-256 key from ML-KEM secret || X25519 secret,
//!   and (domain-separated by info string) a second key for the metadata region
//! - AES-256-GCM: Authenticated encryption with additional data
//! - Context-binding AAD: Each chunk authenticated with chunk index and header hash
//! - Zeroization: Automatic clearing of sensitive data from memory
//! - Chunked encryption: 64KB chunks with unique nonces and authentication
//!
//! # File Format
//! ```text
//! [4 bytes: Magic "PQE1" or "PQE2"]
//! [4 bytes: KEM ciphertext length]
//! [N bytes: KEM ciphertext]
//! [32 bytes: ephemeral X25519 public key]
//! [16 bytes: Salt for HKDF]
//! [12 bytes: Base nonce]
//! --- PQE2 only, below this line ---
//! [4 bytes: cleartext extension region length]
//! [E bytes: cleartext, header-hash-authenticated TLV fields. Forward-compatible:
//!           unknown field IDs are skipped by their own length prefix, so a
//!           future field needs no further magic bump. One field defined today:
//!           field 0x01 (empty value) marks that a 32-byte SHA-256 checksum
//!           trailer follows the last encrypted chunk (see below)]
//! [4 bytes: encrypted metadata region length]
//! [M bytes: AEAD-encrypted TLV (original filename, mtime, atime), under a
//!           key domain-separated from the body key]
//! [Encrypted chunks with 16-byte authentication tags]
//! [32 bytes: optional SHA-256 checksum trailer, present iff extension field
//!           0x01 above is present. Covers every preceding byte of the file
//!           (header through the last chunk) but not itself, computed
//!           incrementally during encryption. Not part of the AEAD scheme and
//!           not authenticated -- a plain checksum for detecting accidental
//!           corruption (bit rot, truncation, a bad copy) without the private
//!           key, via `pqenc verify`. Gives no protection against deliberate
//!           tampering, which the AEAD tags above already catch at decrypt time]
//! ```
//! `pqenc decrypt` accepts both `PQE1` and `PQE2`; `pqenc encrypt` always
//! writes `PQE2` and always appends the checksum trailer. `PQE1` files, and
//! `PQE2` files written before this trailer existed, simply lack it -- absent
//! from the byte stream entirely, not present-but-empty; both `pqenc decrypt`
//! and `pqenc verify` tolerate its absence.
//!
//! # Accepted Risks
//! - AES-GCM integrity guarantees degrade beyond ~64 GiB per file due to birthday-bound
//!   limits on the authentication polynomial. Beyond this limit, attackers with significant
//!   resources may have increased (though still negligible) success forging authentication
//!   tags to modify ciphertext undetected. Encryption remains strong.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use rand::Rng;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::prelude::*;

// Constants
const AES_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const MAX_KEM_CIPHERTEXT_SIZE: usize = 10000;
// Size of the optional SHA-256 checksum trailer appended after the last
// encrypted chunk -- see EXTENSION_FIELD_CHECKSUM_TRAILER below.
const TRAILER_SIZE: usize = 32;
const MAGIC_V1: &[u8] = b"PQE1";
const MAGIC_V2: &[u8] = b"PQE2";
const AAD_CHUNK_TYPE_NORMAL: u8 = 0x00;
const AAD_CHUNK_TYPE_LAST: u8 = 0x01;

// PQE2 header regions. Both length prefixes are attacker-controlled before
// validation, so each region has a generous-but-bounded cap to prevent an
// oversized length claim from driving a huge allocation on read — same role
// as MAX_KEM_CIPHERTEXT_SIZE above.
const MAX_EXTENSION_REGION_SIZE: usize = 65536;
const MAX_METADATA_PLAINTEXT_SIZE: usize = 65536;
const MAX_METADATA_CIPHERTEXT_SIZE: usize = MAX_METADATA_PLAINTEXT_SIZE + TAG_SIZE;

// Domain-separates the metadata region's single AEAD call from body-chunk
// AAD (which uses AAD_CHUNK_TYPE_NORMAL/_LAST) at the byte level, on top of
// the key-level separation from METADATA_KEY_INFO below.
const AAD_CHUNK_TYPE_METADATA: u8 = 0x02;

// Metadata TLV field IDs (PQE2 encrypted region only). Unrecognized IDs are
// skipped, not rejected -- see parse_tlv_fields -- so new fields can be added
// later without another format-version bump.
const METADATA_FIELD_FILENAME: u8 = 0x01;
const METADATA_FIELD_MTIME: u8 = 0x02;
const METADATA_FIELD_ATIME: u8 = 0x03;

// Cleartext extension TLV field IDs (PQE2 extension region only) -- a
// separate namespace from the metadata-region field IDs above, since they're
// different regions. Presence of this field (value must be empty) means a
// 32-byte SHA-256 checksum trailer (TRAILER_SIZE) follows the last encrypted
// chunk -- see the "# File Format" doc comment above and `pqenc verify`.
const EXTENSION_FIELD_CHECKSUM_TRAILER: u8 = 0x01;

/// 8-byte BE i64 Unix seconds + 4-byte BE u32 nanoseconds -- matches
/// filetime::FileTime's own (seconds, nanoseconds) representation exactly,
/// so encode/decode need no unit conversion.
const TIMESTAMP_FIELD_SIZE: usize = 12;

const AES_KEY_INFO: &[u8] = b"pqenc-hybrid-aes-key";
const METADATA_KEY_INFO: &[u8] = b"pqenc-hybrid-metadata-key";

// File permission bits requested at creation, before umask. Not `#[cfg(unix)]`:
// they are named at call sites that compile on every platform, and the helper
// that consumes them ignores them off Unix.

/// Owner-only. Used for encrypted output, decrypted plaintext, and the private key.
const OWNER_ONLY_MODE: u32 = 0o600;

/// Deferred to umask, which is what `File::create` requests. Used for the public
/// key, which is *meant* to be handed out — deliberately not `OWNER_ONLY_MODE`.
const DISTRIBUTABLE_MODE: u32 = 0o666;

// X25519 and hybrid constants
const X25519_PUBLIC_KEY_SIZE: usize = 32;
const X25519_PRIVATE_KEY_SIZE: usize = 32;
const SHARED_SECRET_SIZE: usize = 64; // KEM (32) + X25519 (32)

// ML-KEM-1024 private key layout (FIPS 203 decapsulation key: dk_PKE(1536)
// || ek(1568) || H(ek)(32) || z(32) = 3168 bytes), used to recover the
// public key embedded in a private key file for fingerprinting.
const MLKEM1024_PRIVATE_KEY_SIZE: usize = 3168;
const MLKEM1024_PUBLIC_KEY_OFFSET: usize = 1536;
const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;

// Passphrase-based encryption constants
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_SALT_SIZE: usize = 16;
const ARGON2_KEY_LENGTH: usize = 32;
const PBE_NONCE_SIZE: usize = 12;

// PEM headers
const PEM_PUB_BEGIN: &str = "-----BEGIN PQENC PUBLIC KEY-----";
const PEM_PUB_END: &str = "-----END PQENC PUBLIC KEY-----";
const PEM_PRIV_ENC_BEGIN: &str = "-----BEGIN PQENC ENCRYPTED PRIVATE KEY-----";
const PEM_PRIV_ENC_END: &str = "-----END PQENC ENCRYPTED PRIVATE KEY-----";
const PEM_PRIV_BEGIN: &str = "-----BEGIN PQENC PRIVATE KEY-----";
const PEM_PRIV_END: &str = "-----END PQENC PRIVATE KEY-----";

#[derive(Parser)]
#[command(
    name = "pqenc",
    about = "Post-Quantum File Encryption Tool (ML-KEM-1024 + AES-256-GCM)",
    long_about = None,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = "\
Examples:
  # Generate a new keypair
  pqenc generate-keys --public-key pub.key --private-key priv.key

  # Encrypt a file
  pqenc encrypt --encrypt secret.txt --output secret.enc --public-key pub.key

  # Encrypt from stdin (e.g., piped tar archive)
  tar czf - mydir | pqenc encrypt --encrypt /dev/stdin --output mydir.tar.gz.pqe --public-key pub.key

  # Encrypt from stdin using '-' shorthand
  cat secret.txt | pqenc encrypt --encrypt - --output secret.enc --public-key pub.key

  # Decrypt a file
  pqenc decrypt --decrypt secret.enc --output secret.txt --private-key priv.key

  # Non-interactive (e.g. scripts, CI): pass the passphrase directly
  pqenc decrypt --decrypt secret.enc --output secret.txt --private-key priv.key --passphrase \"$PQENC_PASSPHRASE\"

  # Check a file's structure and checksum without the private key (cron-friendly)
  pqenc verify --verify secret.enc

  # Generate a keypair with no passphrase (e.g. disk already encrypted)
  pqenc generate-keys --public-key pub.key --private-key priv.key --passphrase \"\"

  # Show a key's fingerprint and randomart (works on either half of a keypair)
  pqenc fingerprint --public-key pub.key
  pqenc fingerprint --private-key priv.key
"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys {
        #[arg(long, short = 'p')]
        public_key: String,
        #[arg(long, short = 's')]
        private_key: String,
        #[arg(long, help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Pass an empty value to store/read the private key in plain text (not recommended).")]
        passphrase: Option<String>,
    },
    Encrypt {
        #[arg(long = "encrypt", short = 'i')]
        input: String,
        #[arg(long, short = 'o', help = "Output file (default: <input>.pqe)")]
        output: Option<String>,
        #[arg(long, short = 'p')]
        public_key: String,
    },
    Decrypt {
        #[arg(long = "decrypt", short = 'i', help = "Input file to decrypt (must be a regular file, not stdin or a pipe)")]
        input: String,
        #[arg(long, short = 'o', help = "Output file (default: derived from the original filename embedded in the encrypted file, or by stripping a trailing .pqe from the input path)")]
        output: Option<String>,
        #[arg(long, short = 's')]
        private_key: String,
        #[arg(long, help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Not needed for a plain-text private key; if supplied, it is ignored.")]
        passphrase: Option<String>,
    },
    Verify {
        #[arg(long = "verify", short = 'i', help = "Input file to verify (must be a regular file, not stdin or a pipe)")]
        input: String,
    },
    Fingerprint {
        #[command(flatten)]
        key_source: KeySource,
        #[arg(long, help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Not needed for a plain-text private key; if supplied, it is ignored.")]
        passphrase: Option<String>,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct KeySource {
    /// Public key file to fingerprint
    #[arg(long, short = 'p')]
    public_key: Option<String>,
    /// Private key file to fingerprint (prompts for a passphrase if encrypted)
    #[arg(long, short = 's')]
    private_key: Option<String>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData {
    data: Vec<u8>,
}

impl SensitiveData {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// RAII guard for temporary files that ensures cleanup even on panic.
///
/// Automatically deletes the temporary file when dropped unless explicitly
/// told to keep it (via `disarm()`). This prevents leaking sensitive plaintext
/// if decryption fails or panics, and prevents a partial ciphertext that looks
/// like a completed backup from surviving a failed encryption.
struct TempFileGuard {
    path: Option<String>,
}

impl TempFileGuard {
    fn new(path: String) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard to prevent deletion (call before successful rename)
    fn disarm(&mut self) {
        self.path = None;
    }

    /// Get the path reference
    fn path(&self) -> &str {
        self.path.as_ref().expect("TempFileGuard already disarmed")
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Fsync the directory containing `path`. Syncing a file's data does not
/// guarantee the directory entry pointing to it survives a crash (relevant
/// both for newly-created files and for renames) — the directory itself
/// needs a separate fsync.
#[cfg(unix)]
fn sync_parent_dir(path: &str) -> Result<()> {
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .context("Failed to sync directory to disk")
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &str) -> Result<()> {
    Ok(())
}

/// Create `path` for writing, failing if it already exists (O_CREAT|O_EXCL).
/// The exclusive create is what makes claiming a path atomic and symlink-safe;
/// it must never be replaced by a separate `exists()` check. (An advisory
/// `exists()` check *in addition to* this claim is fine — see `generate_keys`.)
///
/// `mode` is requested before umask and is ignored on non-Unix platforms.
///
/// Returns `io::Result` so callers can attach their own context message.
fn create_new_exclusive(path: &str, mode: u32) -> std::io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
}

/// Create `path` exclusively, write `contents`, fsync the file, and close it.
///
/// Returns a `TempFileGuard` armed on `path`, which the caller disarms once the
/// larger operation has committed. The guard is armed only after the exclusive
/// create succeeds, so it can only ever remove a file this process created — it
/// will never touch a pre-existing file at `path`.
///
/// On failure the partial file is removed before returning, so the caller never
/// has to reason about cleaning up a path it does not yet own.
#[must_use = "the returned guard deletes the file when dropped; bind it and disarm on success"]
fn write_new_file_synced(path: &str, contents: &[u8], mode: u32) -> Result<TempFileGuard> {
    // Claim BEFORE arming the guard. Declaring the guard first would arm it
    // before the exclusive create succeeds, so an EEXIST from a pre-existing
    // file would drop the guard and delete the user's real file.
    let mut f = create_new_exclusive(path, mode)
        .with_context(|| format!("Failed to create {} (already exists or permission denied)", path))?;
    let guard = TempFileGuard::new(path.to_string());

    let write_result = f.write_all(contents);
    let sync_result = write_result.and_then(|()| f.sync_all());
    // Close before the guard can unlink: on Windows, removing an open file
    // fails with a sharing violation and would strand the partial file.
    drop(f);
    sync_result.with_context(|| format!("Failed to write and sync {}", path))?;

    Ok(guard)
}

/// Encode bytes as PEM with custom headers
fn pem_encode(der_bytes: &[u8], begin: &str, end: &str) -> String {
    let b64 = BASE64_STANDARD.encode(der_bytes);
    let lines: Vec<String> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    format!("{}\n{}\n{}\n", begin, lines.join("\n"), end)
}

/// Extract PEM body and decode
fn pem_decode(pem_text: &str, begin: &str, end: &str) -> Result<Vec<u8>> {
    let start = pem_text.find(begin)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM header: {}", begin))?;
    let start = start + begin.len();
    let end_pos = pem_text[start..].find(end)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM footer: {}", end))?;

    let b64 = pem_text[start..start + end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    BASE64_STANDARD.decode(b64.as_bytes())
        .context("Failed to decode base64")
}

/// Derive encryption key from passphrase using Argon2id
fn derive_key_from_passphrase(passphrase: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    use argon2::{Argon2, Algorithm, Version, Params};

    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    if salt.len() != ARGON2_SALT_SIZE {
        bail!("Invalid salt size");
    }

    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_KEY_LENGTH),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; ARGON2_KEY_LENGTH];
    argon2.hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 failed: {}", e))?;

    Ok(SensitiveData::new(key))
}

/// Encrypt composite private key with passphrase
fn encrypt_private_key(composite_key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    use rand::RngExt;

    let salt: [u8; ARGON2_SALT_SIZE] = rand::rng().random();
    let key = derive_key_from_passphrase(passphrase, &salt)?;

    let nonce: [u8; PBE_NONCE_SIZE] = rand::rng().random();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));

    let ciphertext = cipher.encrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: composite_key,
            aad: b"pqenc-private-key-v1",
        }
    ).map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Return: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt private key with passphrase
fn decrypt_private_key(encrypted_blob: &[u8], passphrase: &[u8]) -> Result<SensitiveData> {
    let min_size = ARGON2_SALT_SIZE + PBE_NONCE_SIZE + 1 + 16; // +16 for GCM tag
    if encrypted_blob.len() < min_size {
        bail!("Encrypted data too short");
    }

    let salt = &encrypted_blob[..ARGON2_SALT_SIZE];
    let nonce = &encrypted_blob[ARGON2_SALT_SIZE..ARGON2_SALT_SIZE + PBE_NONCE_SIZE];
    let ciphertext = &encrypted_blob[ARGON2_SALT_SIZE + PBE_NONCE_SIZE..];

    let key = derive_key_from_passphrase(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));

    let plaintext = cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: ciphertext,
            aad: b"pqenc-private-key-v1",
        }
    ).map_err(|_| anyhow::anyhow!("Decryption failed - wrong passphrase or corrupted key"))?;

    Ok(SensitiveData::new(plaintext))
}

/// Parse composite public key: [4-byte len][ML-KEM pk][X25519 pk(32)]
fn parse_public_composite_key(data: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if data.len() < 4 + X25519_PUBLIC_KEY_SIZE {
        bail!("Public key data too short");
    }

    let kem_len = u32::from_be_bytes(
        data[..4].try_into().map_err(|_| anyhow::anyhow!("Failed to read public key length field"))?
    ) as usize;
    if kem_len != MLKEM1024_PUBLIC_KEY_SIZE {
        bail!("Invalid ML-KEM public key length: expected {} bytes, got {}", MLKEM1024_PUBLIC_KEY_SIZE, kem_len);
    }

    let expected_len = 4 + kem_len + X25519_PUBLIC_KEY_SIZE;
    if data.len() != expected_len {
        bail!("Invalid composite public key size");
    }

    let mlkem_pk = data[4..4 + kem_len].to_vec();
    let x25519_pk: [u8; 32] = data[4 + kem_len..].try_into()
        .map_err(|_| anyhow::anyhow!("Failed to extract X25519 public key bytes"))?;

    Ok((mlkem_pk, x25519_pk))
}

/// Parse composite private key: [4-byte len][ML-KEM sk][X25519 sk(32)]
fn parse_private_composite_key(data: &[u8]) -> Result<(SensitiveData, SensitiveData)> {
    if data.len() < 4 + X25519_PRIVATE_KEY_SIZE {
        bail!("Private key data too short");
    }

    let kem_len = u32::from_be_bytes(
        data[..4].try_into().map_err(|_| anyhow::anyhow!("Failed to read private key length field"))?
    ) as usize;
    if kem_len != MLKEM1024_PRIVATE_KEY_SIZE {
        bail!("Invalid ML-KEM private key length: expected {} bytes, got {}", MLKEM1024_PRIVATE_KEY_SIZE, kem_len);
    }

    let expected_len = 4 + kem_len + X25519_PRIVATE_KEY_SIZE;
    if data.len() != expected_len {
        bail!("Invalid composite private key size");
    }

    let mlkem_sk = SensitiveData::new(data[4..4 + kem_len].to_vec());
    let x25519_sk = SensitiveData::new(data[4 + kem_len..].to_vec());

    Ok((mlkem_sk, x25519_sk))
}

/// SHA256 of the composite public key. Hashing the whole blob (both the
/// ML-KEM and X25519 halves together) means drift in either sub-key changes
/// the fingerprint, rather than just the half that drifted.
fn compute_fingerprint(composite_pub_bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(composite_pub_bytes).into()
}

/// Formats a fingerprint digest the way `ssh-keygen` does: `SHA256:` followed
/// by unpadded standard base64.
fn format_fingerprint(digest: &[u8; 32]) -> String {
    format!("SHA256:{}", BASE64_STANDARD_NO_PAD.encode(digest))
}

/// Reconstructs the composite public key from a parsed private key's two
/// halves, so a private key file can be fingerprinted without the
/// corresponding public key file.
///
/// The ML-KEM public key is embedded verbatim inside the ML-KEM secret key
/// (FIPS 203's decapsulation-key layout: `dk_PKE(1536) || ek(1568) ||
/// H(ek)(32) || z(32)`); the X25519 public key is a scalar-to-point
/// derivation, mirroring `generate_keys`.
fn extract_public_from_private(mlkem_sk: &[u8], x25519_sk: &[u8]) -> Result<Vec<u8>> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    if mlkem_sk.len() != MLKEM1024_PRIVATE_KEY_SIZE {
        bail!("Invalid ML-KEM private key size");
    }
    let mut x25519_sk_bytes: [u8; X25519_PRIVATE_KEY_SIZE] = x25519_sk.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 private key size"))?;

    let mlkem_pk = &mlkem_sk[MLKEM1024_PUBLIC_KEY_OFFSET..MLKEM1024_PUBLIC_KEY_OFFSET + MLKEM1024_PUBLIC_KEY_SIZE];

    let x25519_secret = StaticSecret::from(x25519_sk_bytes);
    x25519_sk_bytes.zeroize();
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    let mut composite_pub = Vec::with_capacity(4 + mlkem_pk.len() + X25519_PUBLIC_KEY_SIZE);
    composite_pub.extend_from_slice(&(mlkem_pk.len() as u32).to_be_bytes());
    composite_pub.extend_from_slice(mlkem_pk);
    composite_pub.extend_from_slice(x25519_public.as_bytes());

    Ok(composite_pub)
}

/// Loads a private key from a PEM file, decrypting it with a passphrase if
/// it is encrypted (prompting interactively unless one was supplied). A
/// plain-text key ignores a supplied passphrase, since there is nothing to
/// decrypt.
fn load_private_key(private_key_path: &str, passphrase: Option<String>) -> Result<SensitiveData> {
    let pem_text = fs::read_to_string(private_key_path).context("Failed to read private key")?;

    if pem_text.contains(PEM_PRIV_ENC_BEGIN) {
        let encrypted_blob = pem_decode(&pem_text, PEM_PRIV_ENC_BEGIN, PEM_PRIV_ENC_END)?;
        let mut passphrase = match passphrase {
            Some(p) => p,
            None => {
                let display_path = std::path::absolute(private_key_path)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| private_key_path.to_string());
                eprintln!("Enter passphrase for \"{}\":", display_path);
                rpassword::read_password()?
            }
        };
        let result = decrypt_private_key(&encrypted_blob, passphrase.as_bytes());
        passphrase.zeroize();
        result
    } else if pem_text.contains(PEM_PRIV_BEGIN) {
        if let Some(mut p) = passphrase {
            eprintln!("Note: private key is stored in plain text; ignoring supplied passphrase.");
            p.zeroize();
        }
        Ok(SensitiveData::new(pem_decode(&pem_text, PEM_PRIV_BEGIN, PEM_PRIV_END)?))
    } else {
        if let Some(mut p) = passphrase {
            p.zeroize();
        }
        bail!("Not a valid pqenc private key file: {}", private_key_path);
    }
}

/// Renders an OpenSSH-style "drunken bishop" randomart image for a
/// fingerprint digest: a 17x9 field walked 2 bits at a time (4 steps per
/// input byte), bordered by a title and the hash algorithm name.
fn randomart(digest: &[u8; 32], top_label: &str, bottom_label: &str) -> String {
    const CHARS: &[u8] = b" .o+=*BOX@%&#/^SE";
    const WIDTH: i32 = 17;
    const HEIGHT: i32 = 9;

    let mut field = vec![vec![0u8; HEIGHT as usize]; WIDTH as usize];
    let mut x = WIDTH / 2;
    let mut y = HEIGHT / 2;
    let (start_x, start_y) = (x, y);
    let len = CHARS.len() - 1;

    for &byte in digest {
        let mut input = byte;
        for _ in 0..4 {
            x = (x + if input & 0x1 != 0 { 1 } else { -1 }).clamp(0, WIDTH - 1);
            y = (y + if input & 0x2 != 0 { 1 } else { -1 }).clamp(0, HEIGHT - 1);
            let cell = &mut field[x as usize][y as usize];
            if (*cell as usize) < len - 2 {
                *cell += 1;
            }
            input >>= 2;
        }
    }
    field[start_x as usize][start_y as usize] = (len - 1) as u8;
    field[x as usize][y as usize] = len as u8;

    let mut lines = Vec::with_capacity(HEIGHT as usize + 2);
    lines.push(randomart_border(top_label, WIDTH as usize));
    for row in 0..HEIGHT as usize {
        let mut line = String::with_capacity(WIDTH as usize + 2);
        line.push('|');
        for col in 0..WIDTH as usize {
            line.push(CHARS[field[col][row] as usize] as char);
        }
        line.push('|');
        lines.push(line);
    }
    lines.push(randomart_border(bottom_label, WIDTH as usize));
    lines.join("\n")
}

/// Builds a `+--[label]--+`-style border line, centering the bracketed label
/// the same way OpenSSH does: `left = (width - label.len()) / 2`.
fn randomart_border(label: &str, width: usize) -> String {
    let label = format!("[{}]", label);
    let dashes = width.saturating_sub(label.len());
    let left = dashes / 2;
    let right = dashes - left;
    format!("+{}{}{}+", "-".repeat(left), label, "-".repeat(right))
}

/// Displays the fingerprint and randomart for a public or private key file.
///
/// Exactly one of `public_key_path`/`private_key_path` is supplied (enforced
/// by the CLI's `KeySource` argument group). Both produce an identical
/// fingerprint for the same keypair, since both ultimately hash the same
/// composite public key bytes -- see `extract_public_from_private`.
fn show_fingerprint(
    public_key_path: Option<String>,
    private_key_path: Option<String>,
    passphrase: Option<String>,
) -> Result<()> {
    let (composite_pub, display_path) = if let Some(path) = public_key_path {
        validate_path(&path, true, false, "Public key")?;
        let pem_text = fs::read_to_string(&path).context("Failed to read public key")?;
        let composite_pub = pem_decode(&pem_text, PEM_PUB_BEGIN, PEM_PUB_END)?;
        // Validate structure so a corrupt or foreign file fails clearly.
        parse_public_composite_key(&composite_pub)?;
        (composite_pub, path)
    } else if let Some(path) = private_key_path {
        validate_path(&path, true, false, "Private key")?;
        let composite_priv = load_private_key(&path, passphrase)?;
        let (mlkem_sk, x25519_sk) = parse_private_composite_key(&composite_priv.data)?;
        let composite_pub = extract_public_from_private(&mlkem_sk.data, &x25519_sk.data)?;
        (composite_pub, path)
    } else {
        unreachable!("clap enforces exactly one of --public-key/--private-key")
    };

    let digest = compute_fingerprint(&composite_pub);

    println!("The key fingerprint is:");
    println!("{} {}", format_fingerprint(&digest), display_path);
    println!("The key's randomart image is:");
    println!("{}", randomart(&digest, "ML-KEM-1024", "SHA256"));

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

/// Checks if a path refers to stdin (supports both "-" and "/dev/stdin" conventions)
fn is_stdin_path(path: &str) -> bool {
    path == "-" || path == "/dev/stdin"
}

/// Validates a file path for basic sanity checks.
///
/// # Arguments
/// * `path` - The path to validate
/// * `must_exist` - Whether the file must exist
/// * `allow_stdin` - Whether to allow stdin paths ("-" or "/dev/stdin")
/// * `description` - Description for error messages
fn validate_path(path: &str, must_exist: bool, allow_stdin: bool, description: &str) -> Result<()> {
    if path.is_empty() {
        bail!("{} path cannot be empty", description);
    }

    // Allow stdin paths if requested
    if allow_stdin && is_stdin_path(path) {
        return Ok(());
    }

    let p = std::path::Path::new(path);

    if must_exist && !p.exists() {
        bail!("{} does not exist: {}", description, path);
    }

    if p.exists() && p.is_dir() {
        bail!("{} is a directory, not a file: {}", description, path);
    }

    Ok(())
}

/// Opens input for reading - either a file or stdin
fn open_input(path: &str) -> Result<Box<dyn Read>> {
    if is_stdin_path(path) {
        Ok(Box::new(std::io::stdin()))
    } else {
        Ok(Box::new(File::open(path).context("Failed to open input file")?))
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { public_key, private_key, passphrase } => {
            generate_keys(&public_key, &private_key, passphrase)?;
        }
        Commands::Encrypt { input, output, public_key } => {
            let output = resolve_encrypt_output(&input, output)?;
            encrypt_file(&input, &output, &public_key)?;
        }
        Commands::Decrypt { input, output, private_key, passphrase } => {
            decrypt_file(&input, output.as_deref(), &private_key, passphrase)?;
        }
        Commands::Verify { input } => {
            verify_file(&input)?;
        }
        Commands::Fingerprint { key_source, passphrase } => {
            show_fingerprint(key_source.public_key, key_source.private_key, passphrase)?;
        }
    }

    Ok(())
}

/// Generates a new ML-KEM-1024 + X25519 hybrid keypair and saves to files.
///
/// Creates a hybrid post-quantum key pair using both ML-KEM-1024 and X25519,
/// encodes them in PEM format, and encrypts the private key with a
/// passphrase (or, if the passphrase is empty, stores it in plain text).
///
/// Guarantees:
/// - The private key is written and made durable *before* the public key exists,
///   because a stranded public key whose private half was never written is a
///   silent data-loss trap: everything encrypted to it is unrecoverable.
/// - All-or-nothing. Any failure leaves neither file behind, so a retry is not
///   blocked by a leftover from the previous attempt.
/// - On Unix the private key is 0o600, while the public key follows umask —
///   it is meant to be distributed.
///
/// # Arguments
/// * `public_key_path` - Path where public key will be saved
/// * `private_key_path` - Path where private key will be saved
/// * `passphrase` - If given, used instead of the interactive prompt. An
///   empty passphrase stores the private key in plain text.
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if files already exist, paths are invalid, or key generation fails
fn generate_keys(public_key_path: &str, private_key_path: &str, passphrase: Option<String>) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Validate paths
    validate_path(public_key_path, false, false, "Public key")?;
    validate_path(private_key_path, false, false, "Private key")?;

    if public_key_path == private_key_path {
        bail!("Public and private key paths must differ: {}", public_key_path);
    }

    // Advisory pre-check, in addition to (never instead of) the exclusive create
    // below. Losing this race only changes which error message the user sees; it
    // can never cause a file to be clobbered. Running it here, before ~1-2s of
    // key generation and both passphrase prompts, is the entire point: otherwise
    // the user types a passphrase twice before learning the path was occupied.
    //
    // symlink_metadata rather than exists(): exists() follows symlinks and
    // reports false for a dangling one, where O_EXCL still fails EEXIST.
    for (path, description) in [
        (private_key_path, "Private key"),
        (public_key_path, "Public key"),
    ] {
        if fs::symlink_metadata(path).is_ok() {
            bail!("{} file already exists, refusing to overwrite: {}", description, path);
        }
    }

    // Generate ML-KEM keypair
    let mut key_gen_randomness = [0u8; 64];
    rand::rng().fill_bytes(&mut key_gen_randomness);
    let key_pair = mlkem1024::generate_key_pair(key_gen_randomness);
    let (mut mlkem_secret, mlkem_public) = key_pair.into_parts();
    key_gen_randomness.zeroize();

    // Generate X25519 keypair (static for long-term storage)
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let x25519_secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // Build composite public key: [4-byte len][ML-KEM pk][X25519 pk]
    let mlkem_pk_bytes = mlkem_public.as_slice();
    let mut composite_pub = Vec::new();
    composite_pub.extend_from_slice(&(mlkem_pk_bytes.len() as u32).to_be_bytes());
    composite_pub.extend_from_slice(mlkem_pk_bytes);
    composite_pub.extend_from_slice(x25519_public.as_bytes());

    // Build composite private key: [4-byte len][ML-KEM sk][X25519 sk]
    let mlkem_sk_bytes = mlkem_secret.as_slice();
    let mut composite_priv = Vec::new();
    composite_priv.extend_from_slice(&(mlkem_sk_bytes.len() as u32).to_be_bytes());
    composite_priv.extend_from_slice(mlkem_sk_bytes);
    composite_priv.extend_from_slice(x25519_secret.to_bytes().as_ref());
    // Wrapped immediately so every early-return below (passphrase prompt I/O
    // errors, a passphrase mismatch, or an encrypt_private_key failure) still
    // zeroizes this via ZeroizeOnDrop, not just the success path.
    let mut composite_priv = SensitiveData::new(composite_priv);

    let display_priv_path = std::path::absolute(private_key_path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| private_key_path.to_string());

    // Prompt for a passphrase, unless one was supplied on the command line.
    let (mut passphrase1, mut passphrase2) = match passphrase {
        Some(p) => (p.clone(), p),
        None => {
            eprintln!("Enter passphrase for \"{}\" (empty for no passphrase):", display_priv_path);
            let p1 = rpassword::read_password()?;
            eprintln!("Enter same passphrase again:");
            let p2 = rpassword::read_password()?;
            (p1, p2)
        }
    };

    if passphrase1 != passphrase2 {
        passphrase1.zeroize();
        passphrase2.zeroize();
        bail!("Passphrases do not match");
    }
    let unencrypted = passphrase1.is_empty();
    if unencrypted {
        eprintln!("WARNING: \"{}\" will be stored plain text.", display_priv_path);
    } else if passphrase1.len() < 12 {
        eprintln!("Warning: Passphrase shorter than 12 characters may be weak");
    }

    // Encrypt the private key, unless an empty passphrase opted out of encryption.
    let pem_priv = if unencrypted {
        passphrase1.zeroize();
        passphrase2.zeroize();
        pem_encode(&composite_priv.data, PEM_PRIV_BEGIN, PEM_PRIV_END)
    } else {
        let encrypted_priv = {
            let result = encrypt_private_key(&composite_priv.data, passphrase1.as_bytes());
            passphrase1.zeroize();
            passphrase2.zeroize();
            result?
        };
        pem_encode(&encrypted_priv, PEM_PRIV_ENC_BEGIN, PEM_PRIV_ENC_END)
    };

    // Zeroize sensitive data. MlKemPrivateKey has no Drop/ZeroizeOnDrop — an
    // upstream gap still present as of libcrux-ml-kem 0.0.10 (confirmed: no
    // Zeroize impl behind any feature) — so the real backing bytes are wiped
    // in place via its IndexMut impl. Not followed by `drop(mlkem_secret)`:
    // that type still has no Drop, so an explicit drop would just be
    // clippy::drop_non_drop again.
    mlkem_secret[0..MLKEM1024_PRIVATE_KEY_SIZE].zeroize();
    drop(x25519_secret);
    composite_priv.zeroize();

    // Save as PEM
    let pem_pub = pem_encode(&composite_pub, PEM_PUB_BEGIN, PEM_PUB_END);

    // Private key first. A stranded private key is recoverable — the ML-KEM
    // public key is embedded in it and X25519's is a scalar-to-point derivation
    // — whereas a stranded public key is a silent data-loss trap. The guards
    // below make ordinary failures all-or-nothing; the ordering is what covers
    // what guards structurally cannot (SIGKILL, power loss), since Drop does
    // not run then.
    //
    // Declaration order is also the cleanup order: priv_guard is declared first
    // and therefore dropped last, so a late failure removes the public key (the
    // trap) before the private key. Do not reorder these bindings.
    //
    // Windows note: private-key hardening is unimplemented there. It needs
    // ACLs; the previous set_readonly(false) call was a no-op on a file that
    // had just been created and never had the attribute set.
    let mut priv_guard =
        write_new_file_synced(private_key_path, pem_priv.as_bytes(), OWNER_ONLY_MODE)?;

    // The private key's directory entry must be durable before the public key
    // can exist anywhere. Ordering the writes without ordering the directory
    // syncs would fix only half the problem.
    sync_parent_dir(private_key_path)
        .context("Failed to sync directory containing the private key")?;

    let mut pub_guard =
        write_new_file_synced(public_key_path, pem_pub.as_bytes(), DISTRIBUTABLE_MODE)?;

    // Both syncs are load-bearing even when the keys share a directory: they
    // commit different directory entries, and the first could not have covered
    // the public key because it did not exist yet. Do not deduplicate them.
    sync_parent_dir(public_key_path)
        .context("Failed to sync directory containing the public key")?;

    // Commit. Nothing fallible may run between here and the disarms.
    pub_guard.disarm();
    priv_guard.disarm();

    let digest = compute_fingerprint(&composite_pub);

    println!("Key pair generated successfully");
    println!("  Public key:  {}", public_key_path);
    println!("  Private key: {}", private_key_path);
    println!("  Algorithm:   ML-KEM-1024 + X25519 (hybrid)");
    if unencrypted {
        println!("  Private key is stored in plain text (no passphrase)");
    } else {
        println!("  Private key is passphrase-protected");
    }
    println!();
    println!("Key fingerprint is:");
    println!("{}", format_fingerprint(&digest));
    println!("Key's randomart image is:");
    println!("{}", randomart(&digest, "ML-KEM-1024", "SHA256"));

    Ok(())
}

/// Derives an AES-256 key from a combined secret using HKDF-SHA256.
///
/// Uses HKDF with the provided salt and info string AES_KEY_INFO to derive
/// a 32-byte key suitable for AES-256-GCM.
/// The combined secret should be 64 bytes (32 from ML-KEM + 32 from X25519).
fn derive_aes_key(combined_secret: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    if combined_secret.len() != SHARED_SECRET_SIZE {
        bail!("Combined secret must be {} bytes", SHARED_SECRET_SIZE);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), combined_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(AES_KEY_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
    Ok(SensitiveData::new(okm))
}

/// Derives the PQE2 metadata region's AES-256 key from the same combined
/// secret and salt as `derive_aes_key`, domain-separated by info string
/// alone (METADATA_KEY_INFO vs AES_KEY_INFO). This independence is what
/// makes it safe for the metadata region to reuse `base_nonce` directly as
/// its AEAD nonce rather than deriving a fresh one: the two keys can never
/// collide, and the metadata key is used for exactly one AEAD call per
/// encryption run.
fn derive_metadata_key(combined_secret: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    if combined_secret.len() != SHARED_SECRET_SIZE {
        bail!("Combined secret must be {} bytes", SHARED_SECRET_SIZE);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), combined_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(METADATA_KEY_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
    Ok(SensitiveData::new(okm))
}

use aes_gcm::aead::consts::U12;

/// Derives a nonce by adding a counter to a base nonce.
///
/// Converts the 12-byte base nonce to a u128, adds the counter,
/// and converts back to a 12-byte nonce. Returns an error if the
/// counter would cause an overflow, preventing nonce reuse.
fn get_nonce(base_nonce: &[u8], counter: u64) -> Result<Nonce<U12>> {
    // Convert 12-byte base nonce to u128 (padding with 4 zero bytes at start)
    let base_int = u128::from_be_bytes([
        0, 0, 0, 0,
        base_nonce[0], base_nonce[1], base_nonce[2], base_nonce[3],
        base_nonce[4], base_nonce[5], base_nonce[6], base_nonce[7],
        base_nonce[8], base_nonce[9], base_nonce[10], base_nonce[11],
    ]);

    // Add counter and check for 96-bit overflow (critical for AES-GCM nonce uniqueness)
    let new_int = base_int + counter as u128;
    if new_int >> 96 != 0 {
        bail!("Nonce counter overflow - file too large");
    }

    let bytes = new_int.to_be_bytes();
    // Take last 12 bytes
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&bytes[4..16]);

    Ok(*Nonce::from_slice(&nonce_bytes))
}

/// Builds Additional Authenticated Data (AAD) for AEAD encryption.
///
/// Binds the following context to each encrypted chunk:
/// - chunk_type: 1 byte (0x00 for normal chunk, 0x01 for last chunk)
/// - chunk_index: 8 bytes (u64 big-endian position)
/// - header_hash: 32 bytes (SHA256 of file header)
///
/// This improves misuse resistance by cryptographically binding each chunk
/// to its position and the encryption parameters, preventing chunk reordering,
/// header substitution, and other format-level attacks.
fn build_aad(chunk_type: u8, chunk_index: u64, header_hash: &[u8; 32]) -> [u8; 41] {
    let mut aad = [0u8; 41];
    aad[0] = chunk_type;
    aad[1..9].copy_from_slice(&chunk_index.to_be_bytes());
    aad[9..41].copy_from_slice(header_hash);
    aad
}

/// Builds the AAD for the PQE2 metadata region's single AEAD call:
/// `[AAD_CHUNK_TYPE_METADATA(1)] || prefix_hash(32)`. `prefix_hash` is the
/// SHA256 of the header's fixed-position prefix (magic through base_nonce),
/// computed before the metadata ciphertext exists -- unlike `header_hash`,
/// which covers the *entire* header including the metadata ciphertext and
/// so cannot be computed until after this AEAD call has already happened.
/// Deliberately a different length (33 bytes) than `build_aad`'s 41, so the
/// two AAD "channels" can never be confused even by byte length alone.
fn build_metadata_aad(prefix_hash: &[u8; 32]) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[0] = AAD_CHUNK_TYPE_METADATA;
    aad[1..33].copy_from_slice(prefix_hash);
    aad
}

/// Encodes `[field_id:1][len:4 BE][value:len]` entries back to back.
/// Used for both the PQE2 cleartext extension region and the metadata
/// region's plaintext (before AEAD encryption, in the latter case).
fn encode_tlv_fields(fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (field_id, value) in fields {
        out.push(*field_id);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Parses a `[field_id:1][len:4 BE][value:len]`-encoded region into
/// `(field_id, value)` pairs, without interpreting contents. Errors only on
/// structural corruption (a length prefix that runs past the end of
/// `region`) -- an unrecognized field ID is never an error here. Callers
/// pick out the IDs they understand and ignore the rest, which is what
/// makes both TLV regions forward-compatible with fields added later
/// without another format-version bump.
fn parse_tlv_fields(region: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut fields = Vec::new();
    let mut pos = 0;
    while pos < region.len() {
        if pos + 5 > region.len() {
            bail!("Truncated TLV field header");
        }
        let field_id = region[pos];
        let len = u32::from_be_bytes(region[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5;
        if pos + len > region.len() {
            bail!("Truncated TLV field value");
        }
        fields.push((field_id, &region[pos..pos + len]));
        pos += len;
    }
    Ok(fields)
}

fn encode_timestamp(t: filetime::FileTime) -> [u8; TIMESTAMP_FIELD_SIZE] {
    let mut bytes = [0u8; TIMESTAMP_FIELD_SIZE];
    bytes[0..8].copy_from_slice(&t.unix_seconds().to_be_bytes());
    bytes[8..12].copy_from_slice(&t.nanoseconds().to_be_bytes());
    bytes
}

fn decode_timestamp(bytes: &[u8]) -> Result<filetime::FileTime> {
    if bytes.len() != TIMESTAMP_FIELD_SIZE {
        bail!("Invalid timestamp field length: {}", bytes.len());
    }
    let secs = i64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let nanos = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    Ok(filetime::FileTime::from_unix_time(secs, nanos))
}

/// Original-file metadata captured at encrypt time, embedded (encrypted) in
/// the PQE2 metadata region. `None` for stdin input -- there's no real
/// filename or timestamps to capture from a stream.
struct SourceMetadata {
    filename: Option<String>,
    mtime: filetime::FileTime,
    atime: filetime::FileTime,
}

/// Builds the metadata region's AEAD *plaintext*. `None` input produces an
/// empty (0-field) plaintext -- the region is always present and always
/// AEAD-encrypted, even when there's nothing to say, so header parsing
/// never needs a separate "is metadata present" flag.
fn encode_metadata_plaintext(source: Option<&SourceMetadata>) -> Vec<u8> {
    let Some(s) = source else { return Vec::new(); };
    let mtime_bytes = encode_timestamp(s.mtime);
    let atime_bytes = encode_timestamp(s.atime);
    let mut fields: Vec<(u8, &[u8])> = Vec::new();
    if let Some(name) = &s.filename {
        fields.push((METADATA_FIELD_FILENAME, name.as_bytes()));
    }
    fields.push((METADATA_FIELD_MTIME, &mtime_bytes));
    fields.push((METADATA_FIELD_ATIME, &atime_bytes));
    encode_tlv_fields(&fields)
}

/// Parsed PQE2 metadata region. `filename` is the RAW, unsanitized,
/// potentially attacker-influenced string as embedded by whoever encrypted
/// the file -- callers MUST run it through `sanitize_embedded_filename`
/// before ever using it as a path component.
struct DecodedMetadata {
    filename: Option<String>,
    mtime: Option<filetime::FileTime>,
    atime: Option<filetime::FileTime>,
}

/// Parses already-AEAD-decrypted metadata plaintext. Silently skips any
/// field ID this version doesn't recognize (forward compatibility, see
/// `parse_tlv_fields`). A recognized field with a malformed value (wrong
/// length) is a structural error, not silently skipped.
fn decode_metadata_plaintext(plaintext: &[u8]) -> Result<DecodedMetadata> {
    let mut filename = None;
    let mut mtime = None;
    let mut atime = None;
    for (field_id, value) in parse_tlv_fields(plaintext)? {
        match field_id {
            METADATA_FIELD_FILENAME => {
                filename = Some(String::from_utf8_lossy(value).into_owned());
            }
            METADATA_FIELD_MTIME => {
                mtime = Some(decode_timestamp(value)?);
            }
            METADATA_FIELD_ATIME => {
                atime = Some(decode_timestamp(value)?);
            }
            _ => {} // unknown field, forward-compatible: ignore
        }
    }
    Ok(DecodedMetadata { filename, mtime, atime })
}

/// Validates a filename embedded in decrypted metadata as a single safe
/// path component, or returns `None` to reject it.
///
/// SECURITY-CRITICAL: the embedded filename is attacker-influenced --
/// anyone holding the recipient's public key can encrypt a file naming any
/// string as the "original filename". AEAD authentication proves the
/// metadata wasn't tampered with in transit, NOT that the sender was
/// honest about the name. Whatever this returns, if `Some`, is safe to
/// `Path::join` onto a trusted target directory and can only ever resolve
/// to a direct child of that directory -- never elsewhere. Callers must
/// never use the raw, unsanitized string for anything path-related.
fn sanitize_embedded_filename(raw: &str) -> Option<String> {
    if raw.is_empty() || raw == "." || raw == ".." {
        return None;
    }
    // '/' and '\\' are path separators (the latter rejected on principle,
    // even though this project is Unix-focused): Path::join does not treat
    // an embedded separator as opaque, so leaving one in would let the
    // embedded name introduce subdirectories or, combined with "..",
    // escape the target directory entirely. '\0' is rejected because some
    // OS/FFI layers truncate at NUL, which could silently drop a suffix a
    // human reviewing the name would have seen.
    if raw.contains('/') || raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    Some(raw.to_string())
}

/// Resolves the encrypt output path when `-o` was omitted: `<input>.pqe`.
/// Bails if input is stdin -- there's no filename to derive a default from.
fn resolve_encrypt_output(input_path: &str, output: Option<String>) -> Result<String> {
    match output {
        Some(o) => Ok(o),
        None => {
            if is_stdin_path(input_path) {
                bail!("--output is required when reading from stdin");
            }
            Ok(format!("{}.pqe", input_path))
        }
    }
}

/// Resolves the decrypt output path when `-o` was omitted, in precedence
/// order:
///   (a) a sanitized embedded filename, placed as a sibling of `input_path`
///       (its parent directory, not the current working directory -- this
///       keeps behavior consistent with (b)'s directory-preserving
///       heuristic below);
///   (b) `input_path` with a trailing ".pqe" stripped (directory-preserving);
///   (c) an error asking for an explicit `--output`.
///
/// `embedded_filename` is the RAW metadata field value (or `None` for a
/// PQE1 input, a stdin-sourced PQE2 encryption, or a PQE2 file whose
/// metadata omitted the field) -- sanitized internally, never used verbatim.
/// If sanitization rejects it, this falls through to (b) rather than
/// failing outright, since the field is attacker-influenced and shouldn't
/// be able to force a hard failure a plain `.pqe`-suffixed name would have
/// avoided.
fn resolve_decrypt_output(input_path: &str, embedded_filename: Option<&str>) -> Result<String> {
    if let Some(raw) = embedded_filename {
        if let Some(safe_name) = sanitize_embedded_filename(raw) {
            let parent = std::path::Path::new(input_path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            return Ok(parent.join(safe_name).to_string_lossy().into_owned());
        }
    }
    if let Some(stripped) = input_path.strip_suffix(".pqe") {
        return Ok(stripped.to_string());
    }
    bail!("--output is required: input does not end in .pqe and no filename was embedded in the encrypted file")
}

/// Claims `output_path` exclusively (O_CREAT|O_EXCL) and prepares a sibling
/// temp-file path, returning the output guard armed and the temp path as a
/// plain, unclaimed `String`. Does not create the temp file itself -- callers
/// do that separately (since they may need to do more work first) and must
/// only construct the temp file's own `TempFileGuard` AFTER their
/// `create_new_exclusive` on it succeeds. Arming a guard on the temp path
/// before it's claimed would let an EEXIST collision (this exact random name
/// already occupied, e.g. by an attacker) drop the guard and delete a file
/// this process never created -- the same hazard `write_new_file_synced`
/// documents and avoids. Shared by `encrypt_file`'s one claim site and
/// `decrypt_file`'s two (an explicit `-o` claims immediately; an omitted
/// `-o` claims after the metadata-derived default is known), so the
/// guard-declaration-order contract (the fix for bug 7fc6654) can't drift
/// between call sites.
fn claim_output_and_temp(output_path: &str, claim_context: &str) -> Result<(TempFileGuard, String)> {
    use rand::RngExt;

    create_new_exclusive(output_path, OWNER_ONLY_MODE)
        .context(claim_context.to_string())?;
    let output_guard = TempFileGuard::new(output_path.to_string());

    let temp_path = format!("{}.tmp.{:x}", output_path, rand::rng().random::<u64>());

    Ok((output_guard, temp_path))
}

/// Encrypts a file using ML-KEM-1024 + X25519 + AES-256-GCM.
///
/// Performs hybrid post-quantum encryption:
/// 1. Encapsulates a shared secret using the recipient's ML-KEM-1024 public key
/// 2. Performs X25519 key exchange with ephemeral key
/// 3. Combines both secrets and derives an AES-256 key and a domain-separated
///    metadata key using HKDF-SHA256
/// 4. Captures the input file's basename, mtime, and atime (skipped for stdin)
///    and encrypts them into the header's metadata region
/// 5. Encrypts the file in 64KB chunks using AES-256-GCM with unique nonces
/// 6. Writes encrypted output with header containing KEM ciphertext, X25519 public
///    key, salt, base nonce, and the PQE2 extension/metadata regions
/// 7. Streams into a sibling temp file and renames it into place, so a failed
///    run never leaves a partial output that looks like a completed backup
///
/// # Arguments
/// * `input_path` - Path to plaintext file to encrypt
/// * `output_path` - Path where encrypted file will be written
/// * `public_key_path` - Path to recipient's hybrid public key
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if validation fails, encryption fails, or I/O errors occur
fn encrypt_file(input_path: &str, output_path: &str, public_key_path: &str) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, EphemeralSecret};

    let is_stdin = is_stdin_path(input_path);

    // Check if input is a directory (skip for stdin)
    if !is_stdin {
        let input_p = std::path::Path::new(input_path);
        if input_p.exists() && input_p.is_dir() {
            let dirname = input_p.file_name().and_then(|n| n.to_str()).unwrap_or(input_path);
            bail!(
                "Input file is a directory, not a file: {}\n\n\
                pqenc can only encrypt individual files. To encrypt a directory:\n\
                tar czf - {} | pqenc encrypt --encrypt /dev/stdin --output {}.tar.gz.pqe --public-key {}",
                input_path, dirname, dirname, public_key_path
            );
        }
    }

    // Validate all paths (allow stdin for input)
    validate_path(input_path, true, true, "Input file")?;
    validate_path(output_path, false, false, "Output file")?;
    validate_path(public_key_path, true, false, "Public key")?;

    // Load PEM public key
    let pem_text = fs::read_to_string(public_key_path).context("Failed to read public key")?;
    let composite_bytes = pem_decode(&pem_text, PEM_PUB_BEGIN, PEM_PUB_END)?;
    let (mlkem_pk, x25519_pk) = parse_public_composite_key(&composite_bytes)?;

    // ML-KEM encapsulation
    let mut encaps_randomness = [0u8; 32];
    rand::rng().fill_bytes(&mut encaps_randomness);

    // Deserialize public key (1568 bytes for ML-KEM-1024)
    let mlkem_pk_array: [u8; 1568] = mlkem_pk.as_slice()
        .try_into()
        .context("Invalid ML-KEM public key size")?;
    let public_key = mlkem1024::MlKem1024PublicKey::from(mlkem_pk_array);

    // Encapsulate
    let (ciphertext, mut shared_secret) = mlkem1024::encapsulate(&public_key, encaps_randomness);
    encaps_randomness.zeroize();
    let kem_secret_guard = SensitiveData::new(shared_secret.to_vec());
    shared_secret.zeroize();

    // X25519 exchange (ephemeral for one-time use)
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_public = X25519PublicKey::from(x25519_pk);
    let mut shared_secret_x25519 = ephemeral_secret.diffie_hellman(&recipient_public);

    if shared_secret_x25519.as_bytes() == &[0u8; 32] {
        bail!("X25519 key exchange failed: invalid public key (low-order point detected)");
    }

    // Combine secrets (64 bytes)
    let mut combined_secret = Vec::with_capacity(SHARED_SECRET_SIZE);
    combined_secret.extend_from_slice(kem_secret_guard.data.as_slice());
    combined_secret.extend_from_slice(shared_secret_x25519.as_bytes());
    shared_secret_x25519.zeroize();

    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill_bytes(&mut salt);

    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut base_nonce);

    let aes_key = derive_aes_key(&combined_secret, &salt)?;
    let metadata_key = derive_metadata_key(&combined_secret, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    // Zeroize combined secret
    combined_secret.zeroize();

    let mut fin = open_input(input_path)?;
    let (input_size, source_metadata) = if is_stdin {
        (None, None)
    } else {
        let meta = File::open(input_path)?.metadata()?;
        let filename = std::path::Path::new(input_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        let mtime = filetime::FileTime::from_last_modification_time(&meta);
        let atime = filetime::FileTime::from_last_access_time(&meta);
        (Some(meta.len()), Some(SourceMetadata { filename, mtime, atime }))
    };

    // Claim the output path atomically. O_CREAT|O_EXCL both enforces the
    // "already exists" rejection and prevents TOCTOU/symlink attacks, and it
    // reserves the name for the duration of the run. Streams ciphertext into
    // a sibling temp file and renames over the placeholder on success, so a
    // failure mid-write can never leave a partial .enc at output_path. Guard
    // declaration order is the cleanup contract: dropping in reverse closes
    // fout, unlinks the temp, then unlinks the placeholder.
    //
    // temp_guard is declared here (before fout) but only assigned below,
    // after create_new_exclusive on the temp path succeeds -- arming it any
    // earlier would let an EEXIST collision on that path drop the guard and
    // delete a file this process doesn't own (see claim_output_and_temp).
    // Declaring it here rather than after fout keeps the drop order above
    // intact: fout must close before temp_guard tries to unlink it.
    let (mut output_guard, temp_path) = claim_output_and_temp(
        output_path,
        "Failed to create output file (already exists or permission denied)",
    )?;
    let mut temp_guard: TempFileGuard;
    let mut fout = create_new_exclusive(&temp_path, OWNER_ONLY_MODE)
        .context("Failed to create temporary output file")?;
    temp_guard = TempFileGuard::new(temp_path);

    // Build header and compute hash for AAD
    let kem_ct_len = ciphertext.as_slice().len() as u32;
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC_V2);
    header.extend_from_slice(&kem_ct_len.to_be_bytes());
    header.extend_from_slice(ciphertext.as_slice());
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    use sha2::Digest;

    // prefix_hash binds the metadata region's AEAD call to the fixed header
    // fields above, computed now because the metadata ciphertext doesn't
    // exist yet -- header_hash (below) covers the whole header including
    // the metadata region, so it can't be computed until after this point.
    let prefix_hash: [u8; 32] = Sha256::digest(&header).into();

    // Cleartext extension region: marks that a SHA-256 checksum trailer
    // follows the last chunk (see below). Structurally present for other
    // future fields too (e.g. a header-embedded recipient fingerprint),
    // which can be added without another magic-byte bump.
    let extension_region = encode_tlv_fields(&[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])]);
    header.extend_from_slice(&(extension_region.len() as u32).to_be_bytes());
    header.extend_from_slice(&extension_region);

    // Encrypted metadata region: original filename + mtime/atime, under a
    // key domain-separated from the body key (see derive_metadata_key).
    let mut metadata_plaintext = encode_metadata_plaintext(source_metadata.as_ref());
    let metadata_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&metadata_key.data));
    let metadata_aad = build_metadata_aad(&prefix_hash);
    let metadata_ciphertext = metadata_cipher.encrypt(
        Nonce::from_slice(&base_nonce),
        Payload { msg: metadata_plaintext.as_slice(), aad: &metadata_aad },
    ).map_err(|e| anyhow::anyhow!("Metadata encryption failed: {}", e))?;
    metadata_plaintext.zeroize();
    header.extend_from_slice(&(metadata_ciphertext.len() as u32).to_be_bytes());
    header.extend_from_slice(&metadata_ciphertext);

    // Compute header hash for AAD binding (covers the whole header, including
    // the two regions above)
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    // Write header to file
    fout.write_all(&header)?;

    // Accumulates a SHA-256 over every byte written to fout (header + every
    // chunk's ciphertext), incrementally as it's written -- the whole point
    // is to never buffer the full file just to hash it. Finalized into the
    // trailer once the chunk loop below ends. Orthogonal to the AEAD scheme
    // above: a plain, unauthenticated checksum for detecting accidental
    // corruption without the private key (see `pqenc verify`), not part of
    // chunk authentication.
    let mut trailer_hasher = Sha256::new();
    trailer_hasher.update(&header);

    let mut chunk_index = 0;

    // Allocate buffers once and reuse them
    let mut current_chunk = vec![0u8; CHUNK_SIZE];
    let mut next_chunk = vec![0u8; CHUNK_SIZE];

    // Read first chunk - loop to fill buffer completely (or until EOF)
    let mut n_current = 0;
    while n_current < CHUNK_SIZE {
        let n = fin.read(&mut current_chunk[n_current..])?;
        if n == 0 {
            break;
        }
        n_current += n;
    }

    loop {
        // Read next chunk - loop to fill buffer completely (or until EOF)
        let mut n_next = 0;
        while n_next < CHUNK_SIZE {
            let n = fin.read(&mut next_chunk[n_next..])?;
            if n == 0 {
                break;
            }
            n_next += n;
        }

        let chunk_type = if n_next == 0 { AAD_CHUNK_TYPE_LAST } else { AAD_CHUNK_TYPE_NORMAL };
        let aad = build_aad(chunk_type, chunk_index, &header_hash);

        let nonce = get_nonce(&base_nonce, chunk_index)?;
        let payload = Payload {
            msg: &current_chunk[..n_current],
            aad: &aad,
        };

        let ciphertext = cipher.encrypt(&nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        fout.write_all(&ciphertext)?;
        trailer_hasher.update(&ciphertext);

        chunk_index += 1;

        if n_next == 0 {
            // Zeroize both buffers before exit
            current_chunk.zeroize();
            next_chunk.zeroize();
            break;
        }

        // Swap buffers to avoid reallocation
        std::mem::swap(&mut current_chunk, &mut next_chunk);
        n_current = n_next;
    }

    let trailer: [u8; TRAILER_SIZE] = trailer_hasher.finalize().into();
    fout.write_all(&trailer)?;

    fout.sync_all().context("Failed to sync output file to disk")?;
    // Close before rename: required on Windows, and it guarantees the fd is gone
    // before TempFileGuard can unlink on any later error path.
    drop(fout);

    // Commit. Nothing fallible may run between the rename and the two disarms:
    // an early return in that gap would delete the freshly-renamed good output.
    // This is the bug 7fc6654 fixed in decrypt_file — do not reintroduce it.
    fs::rename(temp_guard.path(), output_path)
        .context("Failed to move encrypted file to final destination")?;
    temp_guard.disarm();
    output_guard.disarm();

    sync_parent_dir(output_path)
        .context("Failed to sync directory after rename; encrypted output may not survive a crash")?;

    println!("File encrypted successfully");
    if let Some(size) = input_size {
        println!("  Input:  {} ({} bytes)", input_path, size);
    } else {
        println!("  Input:  {} (stdin)", input_path);
    }
    println!("  Output: {}", output_path);
    println!("  Using:  ML-KEM-1024 + X25519 + AES-256-GCM");

    let digest = compute_fingerprint(&composite_bytes);
    println!();
    println!("Recipient key fingerprint is:");
    println!("{}", format_fingerprint(&digest));
    println!("Recipient key's randomart image is:");
    println!("{}", randomart(&digest, "ML-KEM-1024", "SHA256"));

    Ok(())
}

/// Result of `parse_header`: everything decrypt_file/verify_file need from
/// the structural-only (no key material required) part of a PQE1/PQE2 file.
struct ParsedHeader {
    is_v2: bool,
    header_bytes: Vec<u8>,
    header_hash: [u8; 32],
    prefix_hash: [u8; 32],
    ciphertext_kem: Vec<u8>,
    ephemeral_x25519_pk: [u8; 32],
    salt: [u8; SALT_SIZE],
    base_nonce: [u8; NONCE_SIZE],
    metadata_ciphertext: Vec<u8>,
    has_trailer: bool,
}

/// Parses and structurally validates a PQE1/PQE2 header: magic bytes,
/// length-prefixed fields, and (PQE2 only) the cleartext extension region
/// and encrypted metadata region -- every check that doesn't require the
/// private key. Shared by `decrypt_file` and `verify_file` so this logic
/// (including the bounds checks on attacker-controlled length prefixes)
/// has exactly one implementation instead of two that can drift apart.
///
/// Leaves `fin` positioned immediately after the header, at the start of
/// the encrypted chunk body.
fn parse_header(fin: &mut File) -> Result<ParsedHeader> {
    use sha2::Digest;

    let mut magic = [0u8; 4];
    fin.read_exact(&mut magic)?;
    let is_v2 = if magic == MAGIC_V1 {
        false
    } else if magic == MAGIC_V2 {
        true
    } else {
        bail!("Invalid file format or version");
    };

    let mut len_bytes = [0u8; 4];
    fin.read_exact(&mut len_bytes)?;
    let kem_ct_len = u32::from_be_bytes(len_bytes) as usize;

    if kem_ct_len == 0 || kem_ct_len > MAX_KEM_CIPHERTEXT_SIZE {
        bail!("Invalid KEM ciphertext length: {}", kem_ct_len);
    }

    let mut ciphertext_kem = vec![0u8; kem_ct_len];
    fin.read_exact(&mut ciphertext_kem)?;

    let mut ephemeral_x25519_pk = [0u8; 32];
    fin.read_exact(&mut ephemeral_x25519_pk)?;

    let mut salt = [0u8; SALT_SIZE];
    fin.read_exact(&mut salt)?;

    let mut base_nonce = [0u8; NONCE_SIZE];
    fin.read_exact(&mut base_nonce)?;

    // Reconstruct header for hash computation (must match encryption order)
    let mut header = Vec::new();
    header.extend_from_slice(&magic);
    header.extend_from_slice(&len_bytes);
    header.extend_from_slice(&ciphertext_kem);
    header.extend_from_slice(&ephemeral_x25519_pk);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    // prefix_hash is the AAD for the metadata region's AEAD call (see
    // build_metadata_aad); computed here, before the metadata region (if
    // any) is read, exactly mirroring how encrypt_file computes it.
    let prefix_hash: [u8; 32] = Sha256::digest(&header).into();

    let mut metadata_ciphertext: Vec<u8> = Vec::new();
    let mut has_trailer = false;
    if is_v2 {
        let mut ext_len_bytes = [0u8; 4];
        fin.read_exact(&mut ext_len_bytes)?;
        let ext_len = u32::from_be_bytes(ext_len_bytes) as usize;
        if ext_len > MAX_EXTENSION_REGION_SIZE {
            bail!("Invalid extension region length: {}", ext_len);
        }
        let mut extension_region = vec![0u8; ext_len];
        fin.read_exact(&mut extension_region)?;
        // Structural validation, plus picking out the one field this version
        // recognizes -- an unrecognized field ID is never an error (forward
        // compatibility), but a recognized field with an unexpected value
        // shape is, matching decode_timestamp's convention for the metadata
        // region.
        let ext_fields = parse_tlv_fields(&extension_region)?;
        for &(field_id, value) in &ext_fields {
            if field_id == EXTENSION_FIELD_CHECKSUM_TRAILER {
                if !value.is_empty() {
                    bail!("Invalid checksum trailer marker: expected an empty value, got {} bytes", value.len());
                }
                has_trailer = true;
            }
        }

        let mut meta_len_bytes = [0u8; 4];
        fin.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_be_bytes(meta_len_bytes) as usize;
        if !(TAG_SIZE..=MAX_METADATA_CIPHERTEXT_SIZE).contains(&meta_len) {
            bail!("Invalid metadata region length: {}", meta_len);
        }
        metadata_ciphertext = vec![0u8; meta_len];
        fin.read_exact(&mut metadata_ciphertext)?;

        header.extend_from_slice(&ext_len_bytes);
        header.extend_from_slice(&extension_region);
        header.extend_from_slice(&meta_len_bytes);
        header.extend_from_slice(&metadata_ciphertext);
    }

    // Compute header hash for AAD binding (covers the whole header,
    // including the two PQE2 regions above when present)
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    Ok(ParsedHeader {
        is_v2,
        header_bytes: header,
        header_hash,
        prefix_hash,
        ciphertext_kem,
        ephemeral_x25519_pk,
        salt,
        base_nonce,
        metadata_ciphertext,
        has_trailer,
    })
}

/// Computes the length of the file's encrypted chunk body -- everything up
/// to (but not including) the optional checksum trailer -- from the raw
/// on-disk file length and the trailer marker parsed from the header, and
/// sanity-checks it against the header size. Shared by decrypt_file and
/// verify_file so this security-relevant arithmetic has exactly one
/// implementation: get this wrong and either the last chunk gets
/// misidentified, or -- more dangerously -- trailer bytes get fed into AEAD
/// decryption as if they were still ciphertext.
///
/// When `has_trailer` is false, `body_end == file_len` -- byte-for-byte what
/// decrypt_file computed before the checksum trailer existed, which is what
/// keeps decryption of older, trailer-less files unchanged.
fn body_end_len(file_len: u64, header_end_pos: u64, has_trailer: bool) -> Result<u64> {
    let body_end = if has_trailer {
        file_len.checked_sub(TRAILER_SIZE as u64)
            .ok_or_else(|| anyhow::anyhow!("Invalid file: too short to contain the declared checksum trailer"))?
    } else {
        file_len
    };
    if body_end < header_end_pos + TAG_SIZE as u64 {
        bail!("Invalid ciphertext: file too short. This may indicate file truncation or corruption.");
    }
    Ok(body_end)
}

/// Decrypts a file encrypted with ML-KEM-1024 + X25519 + AES-256-GCM.
///
/// Performs hybrid post-quantum decryption:
/// 1. If an explicit output path was given, claims it immediately
///    (fail-fast) -- before the checksum preflight below, so an occupied
///    destination is reported without first scanning the whole input file
/// 2. Opens the input file once and runs `verify_open_file` on that handle
///    as a preflight -- header structure (magic bytes, KEM ciphertext,
///    X25519 public key, salt, nonce, and, for PQE2, the cleartext
///    extension and encrypted metadata regions) and, if present, the
///    checksum trailer -- before touching the private key at all, so
///    accidental corruption is reported clearly and cheaply rather than
///    partway through the slower chunk-by-chunk AEAD pass
/// 3. Reads the private key; if it is passphrase-encrypted, obtains the passphrase
///    (prompt, or the supplied one) and decrypts it, otherwise reads it as plain text
/// 4. Rewinds the same file handle (no second `open` on the path -- see
///    `verify_open_file`'s doc comment for why) to the start of the
///    encrypted body
/// 5. Decapsulates the shared secret using the recipient's ML-KEM-1024 private key
/// 6. Performs X25519 key exchange with ephemeral public key
/// 7. Combines secrets and derives the AES-256 key using HKDF-SHA256
/// 8. For PQE2, decrypts and parses the metadata region (original filename, mtime, atime)
/// 9. Resolves the output path if not already claimed in step 1 -- a
///    sanitized embedded filename, or a `.pqe`-stripped fallback
/// 10. Decrypts chunks using AES-256-GCM, verifying authentication tags
/// 11. Deletes partial output and returns error if integrity check fails
/// 12. Best-effort restores mtime/atime from the metadata region, if present
///
/// # Arguments
/// * `input_path` - Path to encrypted file
/// * `output_path` - Path where decrypted file will be written, or `None` to derive
///   one from embedded metadata or the input filename (see `resolve_decrypt_output`)
/// * `private_key_path` - Path to the hybrid private key (passphrase-encrypted or plain text)
/// * `passphrase` - If given, used instead of the interactive prompt (ignored if the key is plain text)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if verification fails, validation fails, wrong key, corrupted file, or authentication fails
fn decrypt_file(input_path: &str, output_path: Option<&str>, private_key_path: &str, passphrase: Option<String>) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Validate all paths (stdin not supported for decryption - requires seekable input)
    validate_path(input_path, true, false, "Input file")?;
    validate_path(private_key_path, true, false, "Private key")?;
    let input_meta = fs::metadata(input_path)
        .context("Failed to read input file metadata")?;
    if !input_meta.is_file() {
        bail!("Input file must be a regular file, not a directory or special file: {}", input_path);
    }

    // If -o was given, claim it immediately (fail-fast: using create_new(true)
    // anchors on a file descriptor rather than checking existence separately,
    // eliminating the check-then-rename TOCTOU window) -- and, crucially,
    // *before* the checksum preflight below, so an occupied destination is
    // reported without first scanning the entire (potentially large) input
    // file. If omitted, claiming is deferred until the metadata-derived
    // default is known (see below), since that requires decrypting the
    // metadata region, which requires the private key -- so for that case
    // the preflight still runs first regardless.
    let early_claim: Option<(String, TempFileGuard, String)> = match output_path {
        Some(o) => {
            validate_path(o, false, false, "Output file")?;
            let (og, temp_path) = claim_output_and_temp(o, "Output file already exists or cannot be created")?;
            Some((o.to_string(), og, temp_path))
        }
        None => None,
    };

    // Preflight: verify structure and (if present) the checksum trailer
    // before doing any key-dependent work -- catches accidental corruption
    // with a clear error before spending time on the private key (which may
    // mean an interactive passphrase prompt) or the chunk-by-chunk AEAD pass.
    //
    // Opens `fin` once here and reuses that exact handle for decryption
    // below (rewound, not reopened) rather than verifying one handle and
    // then reopening `input_path` for a second one -- reopening would leave
    // a window between the check and the decrypt where the file at that
    // path could be swapped out from under it (see verify_open_file's doc
    // comment).
    println!("Running verify...");
    let mut fin = File::open(input_path).context("Failed to open input file")?;
    let verified = verify_open_file(&mut fin, input_path).context("Verification failed; aborting decrypt")?;
    println!("Verify passed. Decrypting...");

    // Read and decrypt (or, for a plain-text key, simply decode) the private key
    let composite_priv = load_private_key(private_key_path, passphrase)?;
    let (mlkem_sk, x25519_sk) = parse_private_composite_key(&composite_priv.data)?;

    let VerifiedFile { parsed, body_end } = verified;
    let header_end_pos = parsed.header_bytes.len() as u64;
    let ParsedHeader {
        is_v2, header_hash, prefix_hash, ciphertext_kem, ephemeral_x25519_pk,
        salt, base_nonce, metadata_ciphertext, has_trailer: _, ..
    } = parsed;

    // Rewind the verified handle back to the start of the encrypted body --
    // verify_open_file left it past the trailer (or past the body, if
    // there's no trailer) after hashing.
    fin.seek(SeekFrom::Start(header_end_pos))
        .context("Failed to rewind verified file handle")?;

    // ML-KEM decapsulation
    // Deserialize private key (3168 bytes for ML-KEM-1024)
    let mut mlkem_sk_array: [u8; 3168] = mlkem_sk.data.as_slice()
        .try_into()
        .context("Invalid ML-KEM secret key size")?;
    let mut private_key = mlkem1024::MlKem1024PrivateKey::from(mlkem_sk_array);
    mlkem_sk_array.zeroize();

    // Deserialize ciphertext (1568 bytes)
    let ciphertext_array: [u8; 1568] = ciphertext_kem.as_slice()
        .try_into()
        .context("Invalid ciphertext size")?;
    let ciphertext = mlkem1024::MlKem1024Ciphertext::from(ciphertext_array);

    // Decapsulate (always succeeds per FIPS 203)
    let mut shared_secret = mlkem1024::decapsulate(&private_key, &ciphertext);
    let kem_secret_guard = SensitiveData::new(shared_secret.to_vec());
    shared_secret.zeroize();
    // private_key's own copy of the secret key isn't covered by the
    // mlkem_sk_array.zeroize() above (that only wiped the original array
    // this struct copied from) — see the identical note in generate_keys.
    private_key[0..MLKEM1024_PRIVATE_KEY_SIZE].zeroize();

    // X25519 exchange - recreate static secret from stored bytes
    let mut x25519_sk_array: [u8; 32] = x25519_sk.data.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 key size"))?;
    let x25519_private = StaticSecret::from(x25519_sk_array);
    x25519_sk_array.zeroize();
    let ephemeral_public = X25519PublicKey::from(ephemeral_x25519_pk);
    let mut shared_secret_x25519 = x25519_private.diffie_hellman(&ephemeral_public);

    if shared_secret_x25519.as_bytes() == &[0u8; 32] {
        bail!("X25519 key exchange failed: invalid ephemeral public key (low-order point detected)");
    }

    // Combine secrets
    let mut combined_secret = Vec::with_capacity(SHARED_SECRET_SIZE);
    combined_secret.extend_from_slice(kem_secret_guard.data.as_slice());
    combined_secret.extend_from_slice(shared_secret_x25519.as_bytes());
    shared_secret_x25519.zeroize();

    let aes_key = derive_aes_key(&combined_secret, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    // Decrypt and parse the metadata region, if present. Doing this before
    // zeroizing combined_secret (needed to derive metadata_key) also means a
    // wrong recipient key is detected here, before any body-chunk work
    // begins, for PQE2 files.
    let decoded_metadata: Option<DecodedMetadata> = if is_v2 {
        let metadata_key = derive_metadata_key(&combined_secret, &salt)?;
        let metadata_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&metadata_key.data));
        let metadata_aad = build_metadata_aad(&prefix_hash);
        let mut metadata_plaintext = metadata_cipher.decrypt(
            Nonce::from_slice(&base_nonce),
            Payload { msg: metadata_ciphertext.as_slice(), aad: &metadata_aad },
        ).map_err(|e| anyhow::anyhow!(
            "Metadata decryption failed (Integrity check failed): {:?}\n\
            Possible causes: Wrong key, corrupted file, or truncation attack.", e
        ))?;
        let decoded = decode_metadata_plaintext(&metadata_plaintext)?;
        metadata_plaintext.zeroize();
        Some(decoded)
    } else {
        None
    };

    // Zeroize combined secret
    combined_secret.zeroize();

    // Resolve the final output path and claim it, now that a metadata-driven
    // default (if needed) is known. An explicit -o was already claimed above.
    let (final_output_path, mut output_guard, temp_path) = match early_claim {
        Some((path, og, temp_path)) => (path, og, temp_path),
        None => {
            let embedded = decoded_metadata.as_ref().and_then(|m| m.filename.as_deref());
            let resolved = resolve_decrypt_output(input_path, embedded)?;
            validate_path(&resolved, false, false, "Output file")?;
            let (og, temp_path) = claim_output_and_temp(&resolved, "Output file already exists or cannot be created")?;
            (resolved, og, temp_path)
        }
    };

    // Create temporary output file with restrictive permissions (0o600 on Unix).
    // temp_guard is armed only now, after the exclusive create succeeds --
    // see claim_output_and_temp's doc comment. fout is explicitly dropped
    // before any later fallible return (below), so unlike encrypt_file's
    // matching claim site, declaration order relative to fout doesn't matter
    // here and no deferred-initialization dance is needed.
    let mut fout = create_new_exclusive(&temp_path, OWNER_ONLY_MODE)
        .context("Failed to create temporary output file")?;
    let mut temp_guard = TempFileGuard::new(temp_path);

    // Perform decryption - any error will trigger cleanup of temp file
    let decrypt_result = (|| -> Result<()> {
        let encrypted_chunk_size = CHUNK_SIZE + TAG_SIZE;
        let mut chunk_index = 0;

        // Running position, bounded by body_end (computed above from the
        // header's trailer marker) rather than the raw file length -- this
        // is what keeps a trailer's bytes from ever being read as if they
        // were still ciphertext. Tracked locally instead of re-querying
        // fin.stream_position() each iteration.
        let mut body_pos = header_end_pos;

        loop {
            let remaining = body_end.saturating_sub(body_pos);
            if remaining == 0 {
                break;
            }
            let read_target = std::cmp::min(encrypted_chunk_size as u64, remaining) as usize;

            // Read up to read_target.
            // We loop to ensure we fill the buffer if possible, though for local files read() usually suffices.
            let mut buffer = vec![0u8; read_target];
            let mut bytes_read = 0;
            while bytes_read < read_target {
                let n = fin.read(&mut buffer[bytes_read..])?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            if bytes_read == 0 {
                break;
            }
            body_pos += bytes_read as u64;

            let chunk_type = if body_pos == body_end { AAD_CHUNK_TYPE_LAST } else { AAD_CHUNK_TYPE_NORMAL };
            let aad = build_aad(chunk_type, chunk_index, &header_hash);

            let nonce = get_nonce(&base_nonce, chunk_index)?;
            let payload = Payload {
                msg: &buffer[..bytes_read],
                aad: &aad,
            };

            let mut plaintext = cipher.decrypt(&nonce, payload)
                .map_err(|e| anyhow::anyhow!(
                    "Decryption failed (Integrity check failed): {:?}\n\
                    Possible causes: Wrong key, corrupted file, or truncation attack.", e
                ))?;

            fout.write_all(&plaintext)?;
            plaintext.zeroize();

            chunk_index += 1;
        }

        Ok(())
    })();

    // Sync temp file contents to disk before considering decryption successful,
    // so a crash right after this call can't leave a truncated "success" output.
    let decrypt_result = decrypt_result.and_then(|_| {
        fout.sync_all().context("Failed to sync decrypted temp file to disk")
    });

    // Ensure file is closed before rename/delete
    drop(fout);

    match decrypt_result {
        Ok(_) => {
            let temp_path = temp_guard.path().to_string();
            fs::rename(&temp_path, &final_output_path)
                .context("Failed to move decrypted file to final destination")?;
            temp_guard.disarm();
            output_guard.disarm();
            sync_parent_dir(&final_output_path)
                .context("Failed to sync directory after rename; decrypted output may not survive a crash")?;

            // Best-effort: restore the original file's mtime/atime if the
            // metadata region carried them. Runs after both disarms (same
            // precedent as sync_parent_dir above) so it can never reintroduce
            // the "nothing fallible between rename and disarm" hazard.
            // Content correctness matters far more than timestamps, so a
            // failure here is a warning, not a decrypt failure.
            if let Some(meta) = &decoded_metadata {
                let restore_result = match (meta.mtime, meta.atime) {
                    (Some(mtime), Some(atime)) => filetime::set_file_times(&final_output_path, atime, mtime),
                    (Some(mtime), None) => filetime::set_file_mtime(&final_output_path, mtime),
                    (None, Some(atime)) => filetime::set_file_atime(&final_output_path, atime),
                    (None, None) => Ok(()),
                };
                if let Err(e) = restore_result {
                    eprintln!("Warning: failed to restore original file timestamps: {}", e);
                }
            }

            println!("File decrypted successfully: {}", final_output_path);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Result of `verify_open_file`: everything the caller needs to continue
/// working with the file it just verified, without re-parsing the header or
/// reopening the path.
struct VerifiedFile {
    parsed: ParsedHeader,
    body_end: u64,
}

/// Checks a PQE1/PQE2 file's magic bytes and header structure, and, if the
/// header's extension region marks a checksum trailer as present,
/// recomputes a SHA-256 over the whole file (minus the trailer itself) and
/// compares it. Needs no private key or passphrase, so it can run
/// unattended (e.g. in cron, right after a backup) as the standalone
/// `pqenc verify` command -- and `decrypt_file` also calls this directly as
/// a preflight before touching any key material, so a corrupted file is
/// rejected clearly and cheaply rather than partway through the AEAD pass.
///
/// This is a plain, unauthenticated checksum, not cryptographic
/// authentication: it catches accidental corruption (bit rot, truncation, a
/// bad copy), not deliberate tampering -- anyone with write access to the
/// file can recompute it after modifying the file. Deliberate tampering is
/// still caught by the AEAD tags at actual decrypt time.
///
/// A file with no trailer (an older PQE2 file predating this feature, or a
/// PQE1 file) still gets the structural checks; the checksum comparison is
/// simply skipped, and that's not itself a failure.
///
/// Takes an already-open handle rather than a path, and leaves it
/// positioned just past whatever it last read (past the trailer, or past
/// the body if there's no trailer). `decrypt_file` relies on this: it opens
/// `fin` once, verifies it here, and then seeks the very same handle back
/// to the start of the body to decrypt -- rather than reopening the path a
/// second time, which would leave a window between the check and the
/// decrypt where the file at that path could be swapped out from under it.
///
/// # Returns
/// * `Ok(VerifiedFile)` if the file is structurally valid (and its checksum matches, when present)
/// * `Err` otherwise -- callers (main) translate this into a non-zero exit code
fn verify_open_file(fin: &mut File, input_path: &str) -> Result<VerifiedFile> {
    let parsed = parse_header(fin)?;
    let header_end_pos = parsed.header_bytes.len() as u64;
    let file_len = fin.metadata()?.len();
    let body_end = body_end_len(file_len, header_end_pos, parsed.has_trailer)?;

    println!("Structure OK: valid {} header", if parsed.is_v2 { "PQE2" } else { "PQE1" });

    if !parsed.has_trailer {
        println!("No checksum trailer present (file predates this feature, or is PQE1); skipping checksum check.");
        println!("VALID (structure only): {}", input_path);
        return Ok(VerifiedFile { parsed, body_end });
    }

    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(&parsed.header_bytes);

    // Read forward from wherever parse_header left `fin` positioned (right
    // after the header) -- the header itself is already hashed from memory
    // above, so there's no need to seek back to the start of the file.
    let mut remaining = body_end - header_end_pos;
    let mut buf = vec![0u8; CHUNK_SIZE];
    while remaining > 0 {
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        fin.read_exact(&mut buf[..to_read])
            .context("Failed to read file while recomputing checksum")?;
        hasher.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }
    let computed: [u8; 32] = hasher.finalize().into();

    let mut trailer = [0u8; TRAILER_SIZE];
    fin.read_exact(&mut trailer).context("Failed to read checksum trailer")?;

    if computed == trailer {
        println!("Checksum OK: matches embedded SHA-256 trailer");
        println!("VALID: {}", input_path);
        Ok(VerifiedFile { parsed, body_end })
    } else {
        bail!(
            "CHECKSUM MISMATCH: file may be corrupted or truncated\n  computed: {}\n  trailer:  {}",
            to_hex(&computed), to_hex(&trailer)
        );
    }
}

/// Standalone `pqenc verify` entry point: validates `input_path`, opens it
/// once, and runs `verify_open_file`. See that function for what's actually
/// checked; this wrapper exists because the CLI command has no further use
/// for the open handle or parsed header once verification is done.
fn verify_file(input_path: &str) -> Result<()> {
    validate_path(input_path, true, false, "Input file")?;
    let input_meta = fs::metadata(input_path)
        .context("Failed to read input file metadata")?;
    if !input_meta.is_file() {
        bail!("Input file must be a regular file, not a directory or special file: {}", input_path);
    }

    let mut fin = File::open(input_path).context("Failed to open input file")?;
    verify_open_file(&mut fin, input_path)?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests;
