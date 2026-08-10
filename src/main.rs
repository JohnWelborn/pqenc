//! Post-Quantum File Encryption Tool
//!
//! Provides hybrid post-quantum encryption using ML-KEM-1024 (NIST FIPS 203)
//! for key encapsulation, X25519 for an additional DH secret, and AES-256-GCM
//! for symmetric encryption. The combined secret (ML-KEM shared secret ||
//! X25519 shared secret) and a per-file salt are HKDF-derived, via distinct
//! domain-separated info strings, into a metadata-region key and one or more
//! body-chunk keys (see "File Format" below).
//!
//! # Security Features
//! - ML-KEM-1024: Post-quantum secure key encapsulation mechanism
//! - X25519: Ephemeral-static Diffie-Hellman mixed with the KEM secret
//! - HKDF-SHA256: Derives the metadata-region key and the body-chunk key(s)
//!   from ML-KEM secret || X25519 secret, each via its own domain-separated
//!   info string
//! - AES-256-GCM: Authenticated encryption with additional data
//! - Context-binding AAD: Each chunk authenticated with its position, the
//!   header hash, the format version, and segment index -- see below
//! - Zeroization: Automatic clearing of sensitive data from memory
//! - Chunked encryption: 64KB chunks with unique nonces and authentication
//! - Segmented rekeying: a fresh, independently-derived AES-256-GCM key
//!   every 8 GiB of plaintext, so no single key ever encrypts more than
//!   8 GiB regardless of total file size
//!
//! # File Format
//! ```text
//! [4 bytes: Magic "PQE3"]
//! [4 bytes: KEM ciphertext length]
//! [N bytes: KEM ciphertext]
//! [32 bytes: ephemeral X25519 public key]
//! [16 bytes: Salt for HKDF]
//! [12 bytes: Base nonce]
//! [4 bytes: cleartext extension region length]
//! [E bytes: cleartext, header-hash-authenticated TLV fields. Forward-compatible:
//!           unknown field IDs are skipped by their own length prefix, so a
//!           future field needs no further magic bump. One field defined today:
//!           field 0x01 (empty value, required) marks that a 32-byte SHA-256
//!           checksum trailer follows the last encrypted chunk (see below)]
//! [4 bytes: encrypted metadata region length]
//! [M bytes: AEAD-encrypted TLV (original filename, mtime, atime), under a
//!           key domain-separated from the body key(s)]
//! [Encrypted chunks with 16-byte authentication tags -- see "Segmented
//!           Body Encryption" below]
//! [32 bytes: SHA-256 checksum trailer. Covers every preceding byte of the
//!           file (header through the last chunk) but not itself, computed
//!           incrementally during encryption. Not part of the AEAD scheme and
//!           not authenticated -- a plain checksum for detecting accidental
//!           corruption (bit rot, truncation, a bad copy) without the private
//!           key, via `pqenc verify`. Gives no protection against deliberate
//!           tampering, which the AEAD tags above already catch at decrypt time]
//! ```
//! `pqenc` only ever reads and writes `PQE3`; the checksum trailer is
//! mandatory on every file.
//!
//! # Segmented Body Encryption
//! The plaintext is divided into fixed `SEGMENT_SIZE` (8 GiB) segments --
//! the final segment may be shorter -- and each is encrypted under an
//! independent AES-256-GCM key:
//! ```text
//! segment_key = HKDF-SHA256-Expand(
//!     PRK = HKDF-Extract(salt, combined_secret),
//!     info = "pqenc-pqe3-body-key" || segment_index (8 bytes, big-endian),
//!     L = 32
//! )
//! ```
//! `CHUNK_SIZE` (64 KiB) evenly divides `SEGMENT_SIZE`, so `CHUNKS_PER_SEGMENT`
//! (131072) is exact and a segment boundary always lands on a chunk edge --
//! no chunk ever spans two segments. Nonces reset to `get_nonce(base_nonce,
//! local_chunk_index)` (`local_chunk_index` starting back at 0) at the start
//! of every segment; this is safe *only* because each segment's key is
//! independent, so the same nonce bytes are never reused under the same key.
//!
//! Each body chunk's AAD is:
//! ```text
//! [1 byte: format version = 0x03]
//! [1 byte: chunk_type -- 0x00 normal, 0x01 = final chunk of the *entire
//!          file*, never merely the final chunk of a segment]
//! [8 bytes: segment_index, big-endian]
//! [8 bytes: local_chunk_index, big-endian, resets to 0 every segment]
//! [32 bytes: header_hash]
//! ```
//! binding every chunk to its exact position in its segment and in the file
//! as a whole -- together with each segment's independent key, this prevents
//! chunk reordering, cross-segment cut-and-paste (a ciphertext chunk from one
//! segment can never be replayed into another segment's position: wrong key
//! *and* wrong AAD), and header substitution.
//!
//! # Private-Key Envelope Format
//! The passphrase-protected private-key blob -- the entire content of a
//! `PQENC ENCRYPTED PRIVATE KEY` PEM file, before PEM-wrapping -- is a
//! small binary envelope with its own version tag, separate from the
//! `PQE3` magic above (that magic versions the encrypted *file* format;
//! this section is about the encrypted *private key* format):
//! ```text
//! [1 byte:  envelope version = 0x01]
//! [1 byte:  KDF algorithm id = 0x01 (Argon2id)]
//! [1 byte:  AEAD algorithm id = 0x01 (AES-256-GCM)]
//! [4 bytes: KDF-params TLV region length, BE]
//! [P bytes: TLV-encoded Argon2id parameters (encode_tlv_fields/
//!           parse_tlv_fields, the same encoding as the main file format's
//!           TLV regions above): memory_cost, time_cost, parallelism, and
//!           key_length, each a 4-byte BE u32 value. All four are
//!           required; an unrecognized extra field ID is ignored, so a
//!           future Argon2 knob can be added without another envelope
//!           version bump]
//! [16 bytes: salt]
//! [12 bytes: nonce]
//! [4 bytes: ciphertext length, BE]
//! [C bytes: AES-256-GCM ciphertext of the composite private key (includes
//!           the 16-byte GCM tag), AAD-bound to every header byte above so
//!           header tampering is rejected]
//! ```
//! `pqenc generate-keys` always writes this envelope, using whatever
//! `ARGON2_MEMORY_COST`/`ARGON2_TIME_COST`/`ARGON2_PARALLELISM`/
//! `ARGON2_KEY_LENGTH` are current at encryption time -- recording them in
//! the envelope is what lets those defaults change in a later release
//! without breaking keys already written under the old values.
//!
//! # Accepted Risks
//! - AES-GCM integrity guarantees degrade beyond ~64 GiB under a single key
//!   due to birthday-bound limits on the authentication polynomial. Every
//!   segment is independently keyed and at most 8 GiB, comfortably inside
//!   the safe bound, regardless of total file size, so this does not apply
//!   to any file `pqenc` produces or reads.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use rand::Rng;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
const MAGIC_V3: &[u8] = b"PQE3";

// Body segmentation. Plaintext is divided into fixed SEGMENT_SIZE segments
// (the final segment may be shorter), each encrypted under its own
// AES-256-GCM key derived via derive_body_key_v3 -- so no single key ever
// encrypts more than SEGMENT_SIZE, regardless of total file size. This is
// what resolves the AES-GCM per-key data-limit concern noted in "Accepted
// Risks" below.
//
// CHUNK_SIZE evenly divides SEGMENT_SIZE (enforced below), so a segment
// boundary always lands exactly on a chunk edge and no chunk ever spans two
// segments.
const SEGMENT_SIZE: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
const CHUNKS_PER_SEGMENT: u64 = SEGMENT_SIZE / CHUNK_SIZE as u64;
const _: () = assert!(
    SEGMENT_SIZE.is_multiple_of(CHUNK_SIZE as u64),
    "SEGMENT_SIZE must be a whole number of CHUNK_SIZE-sized chunks"
);

// Reservation-placeholder marker and staleness threshold for
// claim_output_and_temp's reclaim logic (TODO.md #1). Deliberately does not
// start with MAGIC_V3 above, so it can never be mistaken for real
// ciphertext by anything, including this tool, that inspects the file.
const RESERVATION_MARKER: &[u8] = b"PQENC-RESERVED-PLACEHOLDER\n";

// Minimum age a placeholder must have before it's eligible for reclaim.
// Without this, a second, still-running pqenc process targeting the same
// output_path would look "stale" to a concurrent invocation the instant its
// placeholder is written (its marker content is indistinguishable from a
// genuinely dead one for the run's entire duration), so the second process
// would reclaim (delete) the first one's live claim and race it to the
// final rename -- exactly the clobber this claim mechanism exists to
// prevent. A placeholder from the actual motivating case (SIGKILL, power
// loss, discovered on a later retry) is essentially never retried within
// this window, so this doesn't weaken the fix -- it only means reclaim
// isn't available *yet* in that narrow window, falling back to today's
// plain "already exists" error, never worse than pre-fix behavior.
const RESERVATION_STALE_AGE: std::time::Duration = std::time::Duration::from_secs(300);

const AAD_CHUNK_TYPE_NORMAL: u8 = 0x00;
const AAD_CHUNK_TYPE_LAST: u8 = 0x01;

// Explicit format-version tag bound into every body-chunk AAD (see
// build_aad_v3), on top of header_hash already covering the header's magic
// bytes -- belt-and-suspenders against ever confusing a body chunk AAD with
// the metadata region's build_metadata_aad (33 bytes): build_aad_v3 is 50
// bytes, a length that never collides with it.
const AAD_VERSION_V3: u8 = 0x03;

// Header regions after base_nonce. Both length prefixes are
// attacker-controlled before validation, so each region has a
// generous-but-bounded cap to prevent an oversized length claim from driving
// a huge allocation on read — same role as MAX_KEM_CIPHERTEXT_SIZE above.
const MAX_EXTENSION_REGION_SIZE: usize = 65536;
const MAX_METADATA_PLAINTEXT_SIZE: usize = 65536;
const MAX_METADATA_CIPHERTEXT_SIZE: usize = MAX_METADATA_PLAINTEXT_SIZE + TAG_SIZE;

// Domain-separates the metadata region's single AEAD call from body-chunk
// AAD (which uses AAD_CHUNK_TYPE_NORMAL/_LAST) at the byte level, on top of
// the key-level separation from METADATA_KEY_INFO below.
const AAD_CHUNK_TYPE_METADATA: u8 = 0x02;

// Metadata TLV field IDs (encrypted region only). Unrecognized IDs are
// skipped, not rejected -- see parse_tlv_fields -- so new fields can be
// added later without another format-version bump.
const METADATA_FIELD_FILENAME: u8 = 0x01;
const METADATA_FIELD_MTIME: u8 = 0x02;
const METADATA_FIELD_ATIME: u8 = 0x03;

// Cleartext extension TLV field IDs (extension region only) -- a separate
// namespace from the metadata-region field IDs above, since they're
// different regions. Presence of this field (value must be empty) means a
// 32-byte SHA-256 checksum trailer (TRAILER_SIZE) follows the last encrypted
// chunk -- see the "# File Format" doc comment above and `pqenc verify`.
const EXTENSION_FIELD_CHECKSUM_TRAILER: u8 = 0x01;

/// 8-byte BE i64 Unix seconds + 4-byte BE u32 nanoseconds -- matches
/// filetime::FileTime's own (seconds, nanoseconds) representation exactly,
/// so encode/decode need no unit conversion.
const TIMESTAMP_FIELD_SIZE: usize = 12;

const METADATA_KEY_INFO: &[u8] = b"pqenc-hybrid-metadata-key";

// Per-segment body key HKDF info prefix. The full info value is this prefix
// followed by the 8-byte big-endian segment index (see derive_body_key_v3),
// distinct from METADATA_KEY_INFO so a segment key can never collide with
// the metadata key even if combined_secret/salt were ever reused (they
// never are: both are freshly random per encryption).
const AES_KEY_INFO_V3_PREFIX: &[u8] = b"pqenc-pqe3-body-key";

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

// Private-key envelope format tags (see "Private-Key Envelope Format" doc
// comment above and decrypt_private_key below). A separate version space
// from MAGIC_V3 above -- that versions the encrypted *file* format, these
// version the encrypted *private key* format.
const KEY_ENVELOPE_VERSION_V1: u8 = 0x01;
const KDF_ALG_ARGON2ID: u8 = 0x01;
const AEAD_ALG_AES_256_GCM: u8 = 0x01;

// KDF-params TLV field IDs (V1 envelope only) -- their own namespace,
// separate from METADATA_FIELD_*/EXTENSION_FIELD_* above, since those are
// different TLV regions in a different format.
const KDF_PARAM_FIELD_MEMORY_COST: u8 = 0x01;
const KDF_PARAM_FIELD_TIME_COST: u8 = 0x02;
const KDF_PARAM_FIELD_PARALLELISM: u8 = 0x03;
const KDF_PARAM_FIELD_KEY_LENGTH: u8 = 0x04;

// Bounds on attacker/corruption-controlled length and numeric fields in a V1
// envelope -- same defensive role as MAX_KEM_CIPHERTEXT_SIZE/
// MAX_EXTENSION_REGION_SIZE above: an oversized length claim can't drive a
// huge allocation, and an oversized Argon2 cost claim can't make decrypting
// a corrupted envelope hang for an attacker-chosen amount of time.
const MAX_KEY_ENVELOPE_KDF_PARAMS_SIZE: usize = 4096;
const MAX_KEY_ENVELOPE_CIPHERTEXT_SIZE: usize = 65536;
const MAX_ENVELOPE_ARGON2_MEMORY_COST: u32 = 4 * 1024 * 1024; // KiB (4 GiB)
const MAX_ENVELOPE_ARGON2_TIME_COST: u32 = 100;
const MAX_ENVELOPE_ARGON2_PARALLELISM: u32 = 256;

// AAD literal for the envelope shape decrypt_private_key accepts.
const KEY_ENVELOPE_AAD_V1_PREFIX: &[u8] = b"pqenc-private-key-envelope-v1";

// Size of the composite private key plaintext this tool has always produced
// ([4-byte len][ML-KEM-1024 secret key][X25519 secret key]) -- fixed
// because both key sizes are fixed by their respective schemes. Test-only:
// production code never needs this size as a value (the plaintext is
// whatever `encrypt_private_key` is handed), but test fixtures use it to
// build correctly-sized composite keys.
#[cfg(test)]
const COMPOSITE_PRIVATE_KEY_SIZE: usize = 4 + MLKEM1024_PRIVATE_KEY_SIZE + X25519_PRIVATE_KEY_SIZE;

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
    about = "Post-Quantum File Encryption Tool (ML-KEM-1024 + X25519 hybrid + AES-256-GCM)",
    long_about = None,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = "\
Examples:
  # Generate a new keypair
  pqenc generate-keys --public-key pub.key --private-key priv.key

  # Encrypt a file
  pqenc encrypt secret.txt --output secret.enc --public-key pub.key

  # Decrypt a file
  pqenc decrypt secret.enc --output secret.txt --private-key priv.key

  # Encrypt a directory (tar+gzip into a single compressed archive)
  tar czf - mydir | pqenc encrypt /dev/stdin --output mydir.tar.gz.pqe --public-key pub.key

  # Check an encrypted file for corruption (does not detect tampering)
  pqenc verify secret.enc

  # Show a key's fingerprint and randomart
  pqenc fingerprint pub.key
  pqenc fingerprint priv.key
"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Generate a new ML-KEM-1024 + X25519 hybrid keypair")]
    GenerateKeys {
        #[arg(long, short = 'p')]
        public_key: String,
        #[arg(long, short = 's')]
        private_key: String,
        #[arg(
            long,
            help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Pass an empty value to store/read the private key in plain text (not recommended)."
        )]
        passphrase: Option<String>,
    },
    #[command(about = "Encrypt a file using a public key")]
    Encrypt {
        #[arg(help = "Input file to encrypt (use \"-\" or /dev/stdin to read from a pipe)")]
        input: String,
        #[arg(long, short = 'o', help = "Output file (default: <input>.pqe)")]
        output: Option<String>,
        #[arg(long, short = 'p')]
        public_key: String,
    },
    #[command(about = "Decrypt a file using the private key")]
    Decrypt {
        #[arg(help = "Input file to decrypt (must be a regular file, not stdin or a pipe)")]
        input: String,
        #[arg(
            long,
            short = 'o',
            help = "Output file (default: derived from the original filename embedded in the encrypted file, or by stripping a trailing .pqe from the input path)"
        )]
        output: Option<String>,
        #[arg(long, short = 's')]
        private_key: String,
        #[arg(
            long,
            help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Not needed for a plain-text private key; if supplied, it is ignored."
        )]
        passphrase: Option<String>,
    },
    #[command(
        about = "Check an encrypted file for corruption (does not detect tampering)"
    )]
    Verify {
        #[arg(help = "Input file to verify (must be a regular file, not stdin or a pipe)")]
        input: String,
    },
    #[command(about = "Show a key's fingerprint and randomart")]
    Fingerprint {
        #[arg(help = "Public or private key file to fingerprint (auto-detected)")]
        key: String,
        #[arg(
            long,
            help = "Passphrase for the private key, skipping the interactive prompt. \
            Warning: visible to other users via `ps`/process listings and may be recorded in shell history. \
            Not needed for a plain-text private key or a public key; if supplied and not needed, it is ignored."
        )]
        passphrase: Option<String>,
    },
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
    let mut f = create_new_exclusive(path, mode).with_context(|| {
        format!(
            "Failed to create {} (already exists or permission denied)",
            path
        )
    })?;
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
    let start = pem_text
        .find(begin)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM header: {}", begin))?;
    let start = start + begin.len();
    let end_pos = pem_text[start..]
        .find(end)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM footer: {}", end))?;

    let b64 = pem_text[start..start + end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    BASE64_STANDARD
        .decode(b64.as_bytes())
        .context("Failed to decode base64")
}

/// Argon2id parameters a V1 envelope records -- everything
/// `derive_key_from_passphrase` needs beyond the salt and passphrase
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Argon2Params {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    key_length: u32,
}

impl Argon2Params {
    /// Parameters used for newly-written envelopes -- tracks `ARGON2_*`
    /// above, so a future hardening bump there flows into new keys
    /// automatically without touching this struct.
    const CURRENT: Argon2Params = Argon2Params {
        memory_cost: ARGON2_MEMORY_COST,
        time_cost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        key_length: ARGON2_KEY_LENGTH as u32,
    };
}

/// Derive encryption key from passphrase using Argon2id
fn derive_key_from_passphrase(
    passphrase: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<SensitiveData> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    if salt.len() != ARGON2_SALT_SIZE {
        bail!("Invalid salt size");
    }

    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.key_length as usize),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = vec![0u8; params.key_length as usize];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 failed: {}", e))?;

    Ok(SensitiveData::new(key))
}

/// TLV-encodes Argon2id parameters for a V1 envelope header, reusing the
/// same TLV encoding as the main file format's header regions
/// (`encode_tlv_fields`/`parse_tlv_fields`).
fn encode_kdf_params(params: &Argon2Params) -> Vec<u8> {
    encode_tlv_fields(&[
        (
            KDF_PARAM_FIELD_MEMORY_COST,
            &params.memory_cost.to_be_bytes(),
        ),
        (KDF_PARAM_FIELD_TIME_COST, &params.time_cost.to_be_bytes()),
        (
            KDF_PARAM_FIELD_PARALLELISM,
            &params.parallelism.to_be_bytes(),
        ),
        (KDF_PARAM_FIELD_KEY_LENGTH, &params.key_length.to_be_bytes()),
    ])
}

/// Parses a V1 envelope's KDF-params TLV region. Unlike the main file
/// format's optional TLV fields, all four of these are load-bearing for key
/// derivation, so a missing field is a hard error, not a silently-applied
/// default. An unrecognized extra field ID is still ignored (forward
/// compatibility for a future Argon2 knob).
fn parse_kdf_params(region: &[u8]) -> Result<Argon2Params> {
    let fields = parse_tlv_fields(region)?;

    let mut memory_cost = None;
    let mut time_cost = None;
    let mut parallelism = None;
    let mut key_length = None;

    for (field_id, value) in fields {
        let value: [u8; 4] = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid KDF parameter field length"))?;
        let value = u32::from_be_bytes(value);
        match field_id {
            KDF_PARAM_FIELD_MEMORY_COST => memory_cost = Some(value),
            KDF_PARAM_FIELD_TIME_COST => time_cost = Some(value),
            KDF_PARAM_FIELD_PARALLELISM => parallelism = Some(value),
            KDF_PARAM_FIELD_KEY_LENGTH => key_length = Some(value),
            _ => {} // Unrecognized field: forward-compatible, ignore.
        }
    }

    Ok(Argon2Params {
        memory_cost: memory_cost.context("Missing Argon2 memory_cost parameter")?,
        time_cost: time_cost.context("Missing Argon2 time_cost parameter")?,
        parallelism: parallelism.context("Missing Argon2 parallelism parameter")?,
        key_length: key_length.context("Missing Argon2 key_length parameter")?,
    })
}

/// Encrypt composite private key with passphrase, always writing the
/// current (V1) envelope format -- see the "Private-Key Envelope Format"
/// module doc section for the byte layout.
fn encrypt_private_key(composite_key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    use rand::RngExt;

    let params = Argon2Params::CURRENT;
    let salt: [u8; ARGON2_SALT_SIZE] = rand::rng().random();
    let key = derive_key_from_passphrase(passphrase, &salt, &params)?;

    let nonce: [u8; PBE_NONCE_SIZE] = rand::rng().random();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));

    // Header covers everything the AAD binds: version, algorithm IDs,
    // KDF params, salt, nonce -- but not the ciphertext-length prefix or
    // ciphertext itself, which follow it.
    let mut header = Vec::new();
    header.push(KEY_ENVELOPE_VERSION_V1);
    header.push(KDF_ALG_ARGON2ID);
    header.push(AEAD_ALG_AES_256_GCM);
    let kdf_params = encode_kdf_params(&params);
    header.extend_from_slice(&(kdf_params.len() as u32).to_be_bytes());
    header.extend_from_slice(&kdf_params);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let mut aad = Vec::with_capacity(KEY_ENVELOPE_AAD_V1_PREFIX.len() + header.len());
    aad.extend_from_slice(KEY_ENVELOPE_AAD_V1_PREFIX);
    aad.extend_from_slice(&header);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: composite_key,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(header.len() + 4 + ciphertext.len());
    result.extend_from_slice(&header);
    result.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Reads and advances past the next `n` bytes of `data`, starting at
/// `*pos`. Small cursor helper for `decrypt_private_key`'s sequential,
/// bounds-checked parse -- mirrors `parse_tlv_fields`'s own manual
/// bounds-checking style.
fn take_bytes<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *pos + n > data.len() {
        bail!("Truncated private key envelope");
    }
    let slice = &data[*pos..*pos + n];
    *pos += n;
    Ok(slice)
}

/// Decrypts a V1 private key envelope -- see the "Private-Key Envelope
/// Format" module doc section for the byte layout. Every length-prefixed
/// field is bounds-checked before use, and every parsed Argon2 parameter is
/// validated before being handed to Argon2/AES-GCM: an out-of-range
/// `key_length` would otherwise panic in `Key::<Aes256Gcm>::from_slice`
/// rather than fail gracefully, and an out-of-range memory/time cost could
/// make decrypting a corrupted envelope hang for an attacker-chosen amount
/// of time before even attempting the passphrase.
fn decrypt_private_key(encrypted_blob: &[u8], passphrase: &[u8]) -> Result<SensitiveData> {
    let mut pos = 0usize;

    let version = take_bytes(encrypted_blob, &mut pos, 1)?[0];
    if version != KEY_ENVELOPE_VERSION_V1 {
        bail!("Unrecognized private key envelope version: {}", version);
    }
    let kdf_alg = take_bytes(encrypted_blob, &mut pos, 1)?[0];
    if kdf_alg != KDF_ALG_ARGON2ID {
        bail!(
            "Unrecognized private key envelope KDF algorithm: {}",
            kdf_alg
        );
    }
    let aead_alg = take_bytes(encrypted_blob, &mut pos, 1)?[0];
    if aead_alg != AEAD_ALG_AES_256_GCM {
        bail!(
            "Unrecognized private key envelope AEAD algorithm: {}",
            aead_alg
        );
    }

    let kdf_params_len =
        u32::from_be_bytes(take_bytes(encrypted_blob, &mut pos, 4)?.try_into().unwrap()) as usize;
    if kdf_params_len > MAX_KEY_ENVELOPE_KDF_PARAMS_SIZE {
        bail!("Invalid KDF parameters length: {}", kdf_params_len);
    }
    let kdf_params_region = take_bytes(encrypted_blob, &mut pos, kdf_params_len)?;
    let params = parse_kdf_params(kdf_params_region)?;

    if params.key_length as usize != AES_KEY_SIZE {
        bail!("Unsupported Argon2 key length: {}", params.key_length);
    }
    if params.memory_cost > MAX_ENVELOPE_ARGON2_MEMORY_COST {
        bail!("Argon2 memory cost too large: {}", params.memory_cost);
    }
    if params.time_cost > MAX_ENVELOPE_ARGON2_TIME_COST {
        bail!("Argon2 time cost too large: {}", params.time_cost);
    }
    if params.parallelism == 0 || params.parallelism > MAX_ENVELOPE_ARGON2_PARALLELISM {
        bail!("Argon2 parallelism out of range: {}", params.parallelism);
    }

    let salt = take_bytes(encrypted_blob, &mut pos, ARGON2_SALT_SIZE)?;
    let nonce = take_bytes(encrypted_blob, &mut pos, PBE_NONCE_SIZE)?;

    // Everything up to here is what encrypt_private_key bound into the AAD.
    let header = &encrypted_blob[..pos];

    let ciphertext_len =
        u32::from_be_bytes(take_bytes(encrypted_blob, &mut pos, 4)?.try_into().unwrap()) as usize;
    if !(TAG_SIZE..=MAX_KEY_ENVELOPE_CIPHERTEXT_SIZE).contains(&ciphertext_len) {
        bail!("Invalid private key ciphertext length: {}", ciphertext_len);
    }
    let ciphertext = take_bytes(encrypted_blob, &mut pos, ciphertext_len)?;

    if pos != encrypted_blob.len() {
        bail!("Trailing data after private key envelope");
    }

    let mut aad = Vec::with_capacity(KEY_ENVELOPE_AAD_V1_PREFIX.len() + header.len());
    aad.extend_from_slice(KEY_ENVELOPE_AAD_V1_PREFIX);
    aad.extend_from_slice(header);

    let key = derive_key_from_passphrase(passphrase, salt, &params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Decryption failed - wrong passphrase or corrupted key"))?;

    Ok(SensitiveData::new(plaintext))
}

/// Parse composite public key: [4-byte len][ML-KEM pk][X25519 pk(32)]
fn parse_public_composite_key(data: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if data.len() < 4 + X25519_PUBLIC_KEY_SIZE {
        bail!("Public key data too short");
    }

    let kem_len = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read public key length field"))?,
    ) as usize;
    if kem_len != MLKEM1024_PUBLIC_KEY_SIZE {
        bail!(
            "Invalid ML-KEM public key length: expected {} bytes, got {}",
            MLKEM1024_PUBLIC_KEY_SIZE,
            kem_len
        );
    }

    let expected_len = 4 + kem_len + X25519_PUBLIC_KEY_SIZE;
    if data.len() != expected_len {
        bail!("Invalid composite public key size");
    }

    let mlkem_pk = data[4..4 + kem_len].to_vec();
    let x25519_pk: [u8; 32] = data[4 + kem_len..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to extract X25519 public key bytes"))?;

    Ok((mlkem_pk, x25519_pk))
}

/// Parse composite private key: [4-byte len][ML-KEM sk][X25519 sk(32)]
fn parse_private_composite_key(data: &[u8]) -> Result<(SensitiveData, SensitiveData)> {
    if data.len() < 4 + X25519_PRIVATE_KEY_SIZE {
        bail!("Private key data too short");
    }

    let kem_len = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read private key length field"))?,
    ) as usize;
    if kem_len != MLKEM1024_PRIVATE_KEY_SIZE {
        bail!(
            "Invalid ML-KEM private key length: expected {} bytes, got {}",
            MLKEM1024_PRIVATE_KEY_SIZE,
            kem_len
        );
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
    let mut x25519_sk_bytes: [u8; X25519_PRIVATE_KEY_SIZE] = x25519_sk
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 private key size"))?;

    let mlkem_pk = &mlkem_sk
        [MLKEM1024_PUBLIC_KEY_OFFSET..MLKEM1024_PUBLIC_KEY_OFFSET + MLKEM1024_PUBLIC_KEY_SIZE];

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
        Ok(SensitiveData::new(pem_decode(
            &pem_text,
            PEM_PRIV_BEGIN,
            PEM_PRIV_END,
        )?))
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
/// Auto-detects which half of the keypair `key_path` is by sniffing its PEM
/// header (same style as `load_private_key`'s encrypted-vs-plain-text
/// check). Both halves produce an identical fingerprint for the same
/// keypair, since both ultimately hash the same composite public key bytes
/// -- see `extract_public_from_private`.
fn show_fingerprint(key_path: String, passphrase: Option<String>) -> Result<()> {
    validate_path(&key_path, true, false, "Key")?;
    let pem_text = fs::read_to_string(&key_path).context("Failed to read key file")?;

    let composite_pub = if pem_text.contains(PEM_PUB_BEGIN) {
        if let Some(mut p) = passphrase {
            eprintln!("Note: fingerprinting a public key; ignoring supplied passphrase.");
            p.zeroize();
        }
        let composite_pub = pem_decode(&pem_text, PEM_PUB_BEGIN, PEM_PUB_END)?;
        // Validate structure so a corrupt or foreign file fails clearly.
        parse_public_composite_key(&composite_pub)?;
        composite_pub
    } else if pem_text.contains(PEM_PRIV_BEGIN) || pem_text.contains(PEM_PRIV_ENC_BEGIN) {
        let composite_priv = load_private_key(&key_path, passphrase)?;
        let (mlkem_sk, x25519_sk) = parse_private_composite_key(&composite_priv.data)?;
        extract_public_from_private(&mlkem_sk.data, &x25519_sk.data)?
    } else {
        bail!("Not a valid pqenc public or private key file: {}", key_path);
    };

    let digest = compute_fingerprint(&composite_pub);

    println!("The key fingerprint is:");
    println!("{} {}", format_fingerprint(&digest), key_path);
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
        Ok(Box::new(
            File::open(path).context("Failed to open input file")?,
        ))
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys {
            public_key,
            private_key,
            passphrase,
        } => {
            generate_keys(&public_key, &private_key, passphrase)?;
        }
        Commands::Encrypt {
            input,
            output,
            public_key,
        } => {
            let output = resolve_encrypt_output(&input, output)?;
            encrypt_file(&input, &output, &public_key)?;
        }
        Commands::Decrypt {
            input,
            output,
            private_key,
            passphrase,
        } => {
            decrypt_file(&input, output.as_deref(), &private_key, passphrase)?;
        }
        Commands::Verify { input } => {
            verify_file(&input)?;
        }
        Commands::Fingerprint { key, passphrase } => {
            show_fingerprint(key, passphrase)?;
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
fn generate_keys(
    public_key_path: &str,
    private_key_path: &str,
    passphrase: Option<String>,
) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Validate paths
    validate_path(public_key_path, false, false, "Public key")?;
    validate_path(private_key_path, false, false, "Private key")?;

    if public_key_path == private_key_path {
        bail!(
            "Public and private key paths must differ: {}",
            public_key_path
        );
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
            bail!(
                "{} file already exists, refusing to overwrite: {}",
                description,
                path
            );
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
            eprintln!(
                "Enter passphrase for \"{}\" (empty for no passphrase):",
                display_priv_path
            );
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
        eprintln!(
            "WARNING: \"{}\" will be stored plain text.",
            display_priv_path
        );
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

/// Derives the metadata region's AES-256 key from the combined secret and
/// salt via HKDF-SHA256, domain-separated by info string alone
/// (METADATA_KEY_INFO vs AES_KEY_INFO_V3_PREFIX). This independence is what
/// makes it safe for the metadata region to reuse `base_nonce` directly as
/// its AEAD nonce rather than deriving a fresh one: the two keys can never
/// collide, and the metadata key is used for exactly one AEAD call per
/// encryption run. The combined secret should be 64 bytes (32 from ML-KEM +
/// 32 from X25519).
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

/// Derives the AES-256-GCM key for one body segment from the same combined
/// secret and salt as `derive_metadata_key`, but with a distinct,
/// domain-separated HKDF info value that also folds in the segment index:
/// `AES_KEY_INFO_V3_PREFIX || segment_index (8 bytes BE)`. Every segment
/// index therefore yields an independent key -- this is the entire
/// mechanism that lets body encryption safely reuse `base_nonce` (via
/// `get_nonce`) starting from 0 in every segment: the (key, nonce) pair as a
/// whole is never repeated even though nonce bytes are.
fn derive_body_key_v3(
    combined_secret: &[u8],
    salt: &[u8],
    segment_index: u64,
) -> Result<SensitiveData> {
    if combined_secret.len() != SHARED_SECRET_SIZE {
        bail!("Combined secret must be {} bytes", SHARED_SECRET_SIZE);
    }
    let mut info = Vec::with_capacity(AES_KEY_INFO_V3_PREFIX.len() + 8);
    info.extend_from_slice(AES_KEY_INFO_V3_PREFIX);
    info.extend_from_slice(&segment_index.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(salt), combined_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(&info, &mut okm)
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
        0,
        0,
        0,
        0,
        base_nonce[0],
        base_nonce[1],
        base_nonce[2],
        base_nonce[3],
        base_nonce[4],
        base_nonce[5],
        base_nonce[6],
        base_nonce[7],
        base_nonce[8],
        base_nonce[9],
        base_nonce[10],
        base_nonce[11],
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

/// Builds Additional Authenticated Data for a body chunk.
///
/// Binds:
/// - version: 1 byte (AAD_VERSION_V3), explicit even though `header_hash`
///   already transitively covers the header's magic bytes
/// - chunk_type: 1 byte (0x00 normal, 0x01 -- only for the final chunk of
///   the *entire file*, never merely the final chunk of a segment)
/// - segment_index: 8 bytes (u64 big-endian)
/// - local_chunk_index: 8 bytes (u64 big-endian, resets to 0 every segment)
/// - header_hash: 32 bytes (SHA256 of the complete authenticated header)
///
/// segment_index binds each chunk to its segment (and therefore, combined
/// with derive_body_key_v3, to that segment's unique key) and
/// local_chunk_index binds it to its position within that segment, together
/// preventing chunk reordering and cross-segment cut-and-paste; header_hash
/// prevents header substitution. Deliberately 50 bytes -- a length distinct
/// from `build_metadata_aad`'s 33, so the two AAD "channels" can never be
/// confused even by byte length alone.
fn build_aad_v3(
    chunk_type: u8,
    segment_index: u64,
    local_chunk_index: u64,
    header_hash: &[u8; 32],
) -> [u8; 50] {
    let mut aad = [0u8; 50];
    aad[0] = AAD_VERSION_V3;
    aad[1] = chunk_type;
    aad[2..10].copy_from_slice(&segment_index.to_be_bytes());
    aad[10..18].copy_from_slice(&local_chunk_index.to_be_bytes());
    aad[18..50].copy_from_slice(header_hash);
    aad
}

/// Splits a global (whole-file) chunk index into a `(segment_index,
/// local_chunk_index)` pair under a given segment size, for PQE3's
/// per-segment rekeying. `local_chunk_index` is what resets to 0 at the
/// start of every segment (see `build_aad_v3`, `get_nonce`).
///
/// Takes `chunks_per_segment` as a parameter rather than reading
/// `CHUNKS_PER_SEGMENT` directly so this arithmetic can be exercised at
/// small, test-only segment sizes (to reach multi-segment behavior without
/// an actual 8 GiB fixture) as well as the real constant -- production code
/// always calls this with `CHUNKS_PER_SEGMENT`; the parameter itself is not
/// part of the on-disk format.
///
/// Errors on `chunks_per_segment == 0` (division is otherwise infallible:
/// `chunks_per_segment` is a `u64` divisor checked nonzero here, so neither
/// the division nor the remainder can overflow or panic).
fn segment_and_local_chunk_index(
    global_chunk_index: u64,
    chunks_per_segment: u64,
) -> Result<(u64, u64)> {
    if chunks_per_segment == 0 {
        bail!("chunks_per_segment must be nonzero");
    }
    let segment_index = global_chunk_index / chunks_per_segment;
    let local_chunk_index = global_chunk_index % chunks_per_segment;
    Ok((segment_index, local_chunk_index))
}

/// Builds the AAD for the metadata region's single AEAD call:
/// `[AAD_CHUNK_TYPE_METADATA(1)] || prefix_hash(32)`. `prefix_hash` is the
/// SHA256 of the header's fixed-position prefix (magic through base_nonce),
/// computed before the metadata ciphertext exists -- unlike `header_hash`,
/// which covers the *entire* header including the metadata ciphertext and
/// so cannot be computed until after this AEAD call has already happened.
/// Deliberately a different length (33 bytes) than `build_aad_v3`'s 50, so
/// the two AAD "channels" can never be confused even by byte length alone.
fn build_metadata_aad(prefix_hash: &[u8; 32]) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[0] = AAD_CHUNK_TYPE_METADATA;
    aad[1..33].copy_from_slice(prefix_hash);
    aad
}

/// Encodes `[field_id:1][len:4 BE][value:len]` entries back to back.
/// Used for both the cleartext extension region and the metadata region's
/// plaintext (before AEAD encryption, in the latter case).
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
/// the metadata region. `None` for stdin input -- there's no real filename
/// or timestamps to capture from a stream.
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
    let Some(s) = source else {
        return Vec::new();
    };
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

/// Parsed metadata region. `filename` is the RAW, unsanitized,
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
    Ok(DecodedMetadata {
        filename,
        mtime,
        atime,
    })
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
/// stdin-sourced encryption, or a file whose metadata omitted the field) --
/// sanitized internally, never used verbatim.
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
///
/// The placeholder is not left empty: it holds `RESERVATION_MARKER`,
/// written and fsynced before this function returns. If the process is
/// killed (SIGKILL, power loss) before real output is ever renamed over it
/// -- a case `TempFileGuard::Drop` cannot run for -- the leftover
/// placeholder is later recognizable as pqenc's own, instead of an
/// indistinguishable empty stump that permanently blocks every future run
/// to the same path. On an `AlreadyExists` collision, if the file already
/// there is confirmed, via `is_stale_reservation_placeholder`, to be
/// exactly such a placeholder and at least `RESERVATION_STALE_AGE` old (old
/// enough that it can't plausibly belong to a still-running process), it is
/// removed and the claim retried exactly once. Any other outcome -- real
/// content, wrong size, a symlink, too fresh, or the retry itself failing
/// -- propagates as an error unchanged, same as before this reclaim
/// behavior existed.
fn claim_output_and_temp(
    output_path: &str,
    claim_context: &str,
) -> Result<(TempFileGuard, String)> {
    use rand::RngExt;

    let output_guard = match create_reservation_placeholder(output_path) {
        Ok(guard) => guard,
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                && is_stale_reservation_placeholder(output_path) =>
        {
            fs::remove_file(output_path)
                .context("Failed to remove stale reservation placeholder for reclaim")?;
            // Retry exactly once. If this also fails -- e.g. a genuine race
            // with another process that claimed the path in the instant
            // between the check above and this create -- propagate that
            // second error untouched; no loop, no repeated retries.
            create_reservation_placeholder(output_path).context(claim_context.to_string())?
        }
        Err(e) => return Err(e).context(claim_context.to_string()),
    };

    let temp_path = format!("{}.tmp.{:x}", output_path, rand::rng().random::<u64>());

    Ok((output_guard, temp_path))
}

/// Creates `output_path` exclusively and writes+syncs `RESERVATION_MARKER`
/// into it, returning a `TempFileGuard` armed on it once both the create and
/// the write/sync have succeeded. Returns the raw `std::io::Error` from
/// `create_new_exclusive`, uncontextualized, on failure -- so
/// `claim_output_and_temp` can inspect `.kind()` to decide whether an
/// `AlreadyExists` collision is eligible for reclaim before any anyhow
/// context is attached.
#[must_use = "the returned guard deletes the placeholder when dropped; bind it and disarm on success"]
fn create_reservation_placeholder(output_path: &str) -> std::io::Result<TempFileGuard> {
    let mut f = create_new_exclusive(output_path, OWNER_ONLY_MODE)?;
    let guard = TempFileGuard::new(output_path.to_string());

    let write_result = f.write_all(RESERVATION_MARKER);
    let sync_result = write_result.and_then(|()| f.sync_all());
    // Close before any early return below: on Windows, removing an open
    // file (via TempFileGuard's Drop, if this returns Err) fails with a
    // sharing violation and would strand the placeholder -- same reasoning
    // write_new_file_synced documents.
    drop(f);
    sync_result?;

    Ok(guard)
}

/// Returns true iff `path` is exactly pqenc's own stale reservation
/// placeholder, safe to delete and reclaim: a *regular file*
/// (`fs::symlink_metadata`, never `fs::metadata` -- a symlink planted at
/// `path` must never be followed) of exactly `RESERVATION_MARKER.len()`
/// bytes, whose content is byte-for-byte `RESERVATION_MARKER`, and whose
/// mtime is at least `RESERVATION_STALE_AGE` old. Anything else -- wrong
/// type, wrong size, wrong content, an unreadable/future mtime, or an mtime
/// that's too recent -- returns false, and the caller must treat the path
/// as a real, untouchable file. Fails safe throughout: any ambiguity or
/// I/O error means "not stale."
fn is_stale_reservation_placeholder(path: &str) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() != RESERVATION_MARKER.len() as u64 {
        return false;
    }
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
        return false; // clock skew (mtime in the future) -- don't reclaim
    };
    if age < RESERVATION_STALE_AGE {
        return false;
    }
    fs::read(path)
        .map(|contents| contents == RESERVATION_MARKER)
        .unwrap_or(false)
}

/// Supplies the AES-256-GCM cipher, nonce, and AAD to use for one body
/// chunk: an independent key per `chunks_per_segment` chunks (see
/// `derive_body_key_v3`), lazily derived and cached, since both
/// `encrypt_file_with_segment_size`'s and `decrypt_file_with_segment_size`'s
/// chunk loops process chunks in strictly increasing global-index order (so
/// a segment's key is derived at most once, the first time that segment is
/// entered). Nonces reset to `get_nonce(base_nonce, local_chunk_index)`
/// (starting back at 0) at every segment boundary -- safe only because
/// `combined_secret` retained here means every segment's key is
/// independent, so the (key, nonce) pair as a whole is never reused even
/// though nonce bytes are. `combined_secret` is held as `SensitiveData` for
/// exactly as long as body encryption/decryption needs it and is zeroized
/// via `ZeroizeOnDrop` whenever this value drops, on every exit path
/// (including a `?` mid-loop).
struct BodyCipherProvider {
    combined_secret: SensitiveData,
    salt: [u8; SALT_SIZE],
    chunks_per_segment: u64,
    cached_segment: Option<(u64, Aes256Gcm)>,
}

impl BodyCipherProvider {
    fn new(combined_secret: SensitiveData, salt: [u8; SALT_SIZE], chunks_per_segment: u64) -> Self {
        BodyCipherProvider {
            combined_secret,
            salt,
            chunks_per_segment,
            cached_segment: None,
        }
    }

    /// Returns `(cipher, nonce, aad)` for the chunk at `global_chunk_index`.
    /// `chunk_type` is `AAD_CHUNK_TYPE_LAST` iff this is the true final
    /// chunk of the entire file (never merely the final chunk of a
    /// segment).
    fn params_for(
        &mut self,
        global_chunk_index: u64,
        chunk_type: u8,
        header_hash: &[u8; 32],
        base_nonce: &[u8; NONCE_SIZE],
    ) -> Result<(&Aes256Gcm, Nonce<U12>, Vec<u8>)> {
        let (segment_index, local_chunk_index) =
            segment_and_local_chunk_index(global_chunk_index, self.chunks_per_segment)?;

        // Transient immutable reborrow, collapsed to a bool before any
        // mutation happens below -- never overlaps with the `&mut` reborrow
        // that follows, so this satisfies the borrow checker without
        // `unsafe` or a second lookup.
        let needs_new_key = self
            .cached_segment
            .as_ref()
            .map(|(cached_index, _)| *cached_index != segment_index)
            .unwrap_or(true);

        if needs_new_key {
            let key =
                derive_body_key_v3(&self.combined_secret.data, &self.salt[..], segment_index)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));
            self.cached_segment = Some((segment_index, cipher));
            // `key` (SensitiveData) drops here and zeroizes its raw bytes --
            // the AES round-key schedule already expanded into `cipher` no
            // longer needs them.
        }
        let cipher = &self.cached_segment.as_ref().unwrap().1;

        let aad = build_aad_v3(chunk_type, segment_index, local_chunk_index, header_hash);
        let nonce = get_nonce(base_nonce, local_chunk_index)?;
        Ok((cipher, nonce, aad.to_vec()))
    }
}

/// Concatenates the ML-KEM and X25519 shared secrets into a single 64-byte
/// `SensitiveData`, zeroizing the X25519 half in place once copied. Shared by
/// `encrypt_file_with_segment_size` and `decrypt_file_with_segment_size` so
/// this has exactly one implementation. Takes both secrets by reference
/// rather than by value: `kem_secret`'s own `ZeroizeOnDrop` still fires in
/// the caller as usual, and `x25519_secret.zeroize()` runs on the caller's
/// actual variable via `&mut` -- no extra copy of either secret is created
/// here for zeroizing to miss.
fn combine_secrets(
    kem_secret: &SensitiveData,
    x25519_secret: &mut x25519_dalek::SharedSecret,
) -> SensitiveData {
    let mut combined = Vec::with_capacity(SHARED_SECRET_SIZE);
    combined.extend_from_slice(kem_secret.data.as_slice());
    combined.extend_from_slice(x25519_secret.as_bytes());
    x25519_secret.zeroize();
    SensitiveData::new(combined)
}

/// Reads from `r` into `buf` until `buf` is completely full or `r` hits EOF,
/// looping since a single `read()` call is not guaranteed to fill the
/// buffer. Returns the number of bytes actually filled (less than
/// `buf.len()` iff EOF was hit first). Shared by the encrypt and decrypt
/// chunk-read loops; takes `&mut dyn Read` rather than a generic `impl Read`
/// because those loops read from different concrete types (`Box<dyn Read>`
/// vs `File`).
fn fill_buffer(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Encrypts a file using ML-KEM-1024 + X25519 + AES-256-GCM, always writing
/// the current format (PQE3). See `encrypt_file_with_segment_size` for the
/// real implementation; this is a thin wrapper pinning `chunks_per_segment`
/// to the real `CHUNKS_PER_SEGMENT` constant.
fn encrypt_file(input_path: &str, output_path: &str, public_key_path: &str) -> Result<()> {
    encrypt_file_with_segment_size(input_path, output_path, public_key_path, CHUNKS_PER_SEGMENT)
}

/// Performs hybrid post-quantum encryption, writing a PQE3 file:
/// 1. Encapsulates a shared secret using the recipient's ML-KEM-1024 public key
/// 2. Performs X25519 key exchange with ephemeral key
/// 3. Combines both secrets and derives a domain-separated metadata key using
///    HKDF-SHA256 (body keys are derived per-segment, lazily, in step 5)
/// 4. Captures the input file's basename, mtime, and atime (skipped for stdin)
///    and encrypts them into the header's metadata region
/// 5. Encrypts the file in 64KB chunks using AES-256-GCM, rekeying to a fresh,
///    independently HKDF-derived key every `chunks_per_segment` chunks (see
///    `BodyCipherProvider`)
/// 6. Writes encrypted output with header containing KEM ciphertext, X25519 public
///    key, salt, base nonce, and the extension/metadata regions
/// 7. Streams into a sibling temp file and renames it into place, so a failed
///    run never leaves a partial output that looks like a completed backup
///
/// # Arguments
/// * `input_path` - Path to plaintext file to encrypt
/// * `output_path` - Path where encrypted file will be written
/// * `public_key_path` - Path to recipient's hybrid public key
/// * `chunks_per_segment` - Number of `CHUNK_SIZE` chunks per rekey; production
///   callers must always pass `CHUNKS_PER_SEGMENT` (see `encrypt_file`) --
///   this is a test-only seam, not a format parameter, and is not stored
///   anywhere in the output
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if validation fails, encryption fails, or I/O errors occur
fn encrypt_file_with_segment_size(
    input_path: &str,
    output_path: &str,
    public_key_path: &str,
    chunks_per_segment: u64,
) -> Result<()> {
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    let is_stdin = is_stdin_path(input_path);

    // Check if input is a directory (skip for stdin)
    if !is_stdin {
        let input_p = std::path::Path::new(input_path);
        if input_p.exists() && input_p.is_dir() {
            let dirname = input_p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(input_path);
            bail!(
                "Input file is a directory, not a file: {}\n\n\
                pqenc can only encrypt individual files. To encrypt a directory:\n\
                tar czf - {} | pqenc encrypt /dev/stdin --output {}.tar.gz.pqe --public-key {}",
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
    let mlkem_pk_array: [u8; 1568] = mlkem_pk
        .as_slice()
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

    // Combine secrets (64 bytes). Wrapped in SensitiveData immediately so
    // every exit path below -- including a `?` early return, before it's
    // ever moved into BodyCipherProvider -- zeroizes it via ZeroizeOnDrop,
    // rather than relying on a manual `.zeroize()` call that only ran on a
    // specific success path.
    let combined_secret = combine_secrets(&kem_secret_guard, &mut shared_secret_x25519);

    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill_bytes(&mut salt);

    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut base_nonce);

    // No whole-file body key: PQE3 derives one independent key per segment,
    // lazily, inside BodyCipherProvider once the header (and therefore
    // header_hash) is known below.
    let metadata_key = derive_metadata_key(&combined_secret.data, &salt)?;

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
        (
            Some(meta.len()),
            Some(SourceMetadata {
                filename,
                mtime,
                atime,
            }),
        )
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
    header.extend_from_slice(MAGIC_V3);
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
    let metadata_ciphertext = metadata_cipher
        .encrypt(
            Nonce::from_slice(&base_nonce),
            Payload {
                msg: metadata_plaintext.as_slice(),
                aad: &metadata_aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("Metadata encryption failed: {}", e))?;
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

    // combined_secret moves in here -- still needed to derive each
    // segment's key lazily as the loop below reaches it; now zeroizes
    // whenever body_provider drops (the end of this function, on every
    // exit path, including a `?` mid-loop).
    let mut body_provider = BodyCipherProvider::new(combined_secret, salt, chunks_per_segment);

    let mut chunk_index: u64 = 0;

    // Allocate buffers once and reuse them
    let mut current_chunk = vec![0u8; CHUNK_SIZE];
    let mut next_chunk = vec![0u8; CHUNK_SIZE];

    // Read first chunk - loop to fill buffer completely (or until EOF)
    let mut n_current = fill_buffer(&mut fin, &mut current_chunk)?;

    loop {
        // Read next chunk - loop to fill buffer completely (or until EOF)
        let n_next = fill_buffer(&mut fin, &mut next_chunk)?;

        let chunk_type = if n_next == 0 {
            AAD_CHUNK_TYPE_LAST
        } else {
            AAD_CHUNK_TYPE_NORMAL
        };

        let (cipher, nonce, aad) =
            body_provider.params_for(chunk_index, chunk_type, &header_hash, &base_nonce)?;
        let payload = Payload {
            msg: &current_chunk[..n_current],
            aad: aad.as_slice(),
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        fout.write_all(&ciphertext)?;
        trailer_hasher.update(&ciphertext);

        chunk_index = chunk_index
            .checked_add(1)
            .context("Chunk counter overflow -- file too large")?;

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

    fout.sync_all()
        .context("Failed to sync output file to disk")?;
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

    sync_parent_dir(output_path).context(
        "Failed to sync directory after rename; encrypted output may not survive a crash",
    )?;

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
/// the structural-only (no key material required) part of a PQE3 file.
struct ParsedHeader {
    header_bytes: Vec<u8>,
    header_hash: [u8; 32],
    prefix_hash: [u8; 32],
    ciphertext_kem: Vec<u8>,
    ephemeral_x25519_pk: [u8; 32],
    salt: [u8; SALT_SIZE],
    base_nonce: [u8; NONCE_SIZE],
    metadata_ciphertext: Vec<u8>,
}

/// Parses and structurally validates a PQE3 header: magic bytes,
/// length-prefixed fields, the cleartext extension region, and the
/// encrypted metadata region -- every check that doesn't require the
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
    if magic != MAGIC_V3 {
        bail!("Invalid file format or version");
    }

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
    let mut has_trailer = false;
    for &(field_id, value) in &ext_fields {
        if field_id == EXTENSION_FIELD_CHECKSUM_TRAILER {
            if !value.is_empty() {
                bail!(
                    "Invalid checksum trailer marker: expected an empty value, got {} bytes",
                    value.len()
                );
            }
            has_trailer = true;
        }
    }
    if !has_trailer {
        bail!("Missing required checksum trailer");
    }

    let mut meta_len_bytes = [0u8; 4];
    fin.read_exact(&mut meta_len_bytes)?;
    let meta_len = u32::from_be_bytes(meta_len_bytes) as usize;
    if !(TAG_SIZE..=MAX_METADATA_CIPHERTEXT_SIZE).contains(&meta_len) {
        bail!("Invalid metadata region length: {}", meta_len);
    }
    let mut metadata_ciphertext = vec![0u8; meta_len];
    fin.read_exact(&mut metadata_ciphertext)?;

    header.extend_from_slice(&ext_len_bytes);
    header.extend_from_slice(&extension_region);
    header.extend_from_slice(&meta_len_bytes);
    header.extend_from_slice(&metadata_ciphertext);

    // Compute header hash for AAD binding (covers the whole header)
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    Ok(ParsedHeader {
        header_bytes: header,
        header_hash,
        prefix_hash,
        ciphertext_kem,
        ephemeral_x25519_pk,
        salt,
        base_nonce,
        metadata_ciphertext,
    })
}

/// Computes the length of the file's encrypted chunk body -- everything up
/// to (but not including) the checksum trailer -- from the raw on-disk file
/// length, and sanity-checks it against the header size. Shared by
/// decrypt_file and verify_file so this security-relevant arithmetic has
/// exactly one implementation: get this wrong and either the last chunk
/// gets misidentified, or -- more dangerously -- trailer bytes get fed into
/// AEAD decryption as if they were still ciphertext.
fn body_end_len(file_len: u64, header_end_pos: u64) -> Result<u64> {
    let body_end = file_len.checked_sub(TRAILER_SIZE as u64).ok_or_else(|| {
        anyhow::anyhow!("Invalid file: too short to contain the declared checksum trailer")
    })?;
    if body_end < header_end_pos + TAG_SIZE as u64 {
        bail!(
            "Invalid ciphertext: file too short. This may indicate file truncation or corruption."
        );
    }
    Ok(body_end)
}

/// Decrypts a PQE3 file encrypted with ML-KEM-1024 + X25519 + AES-256-GCM.
/// See `decrypt_file_with_segment_size` for the real implementation; this is
/// a thin wrapper pinning `chunks_per_segment` to the real
/// `CHUNKS_PER_SEGMENT` constant.
fn decrypt_file(
    input_path: &str,
    output_path: Option<&str>,
    private_key_path: &str,
    passphrase: Option<String>,
) -> Result<()> {
    decrypt_file_with_segment_size(
        input_path,
        output_path,
        private_key_path,
        passphrase,
        CHUNKS_PER_SEGMENT,
    )
}

/// Performs hybrid post-quantum decryption:
/// 1. If an explicit output path was given, claims it immediately
///    (fail-fast) -- before the checksum preflight below, so an occupied
///    destination is reported without first scanning the whole input file
/// 2. Opens the input file once and runs `verify_open_file` on that handle
///    as a preflight -- header structure (magic bytes, KEM ciphertext,
///    X25519 public key, salt, nonce, the cleartext extension and encrypted
///    metadata regions) and the checksum trailer -- before touching the
///    private key at all, so accidental corruption is reported clearly and
///    cheaply rather than partway through the slower chunk-by-chunk AEAD pass
/// 3. Reads the private key; if it is passphrase-encrypted, obtains the passphrase
///    (prompt, or the supplied one) and decrypts it, otherwise reads it as plain text
/// 4. Rewinds the same file handle (no second `open` on the path -- see
///    `verify_open_file`'s doc comment for why) to the start of the
///    encrypted body
/// 5. Decapsulates the shared secret using the recipient's ML-KEM-1024 private key
/// 6. Performs X25519 key exchange with ephemeral public key
/// 7. Combines secrets, retaining the combined secret to derive each body
///    segment's key lazily as the chunk loop reaches it (see `BodyCipherProvider`)
/// 8. Decrypts and parses the metadata region (original filename, mtime, atime)
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
/// * `chunks_per_segment` - rekey cadence. Production callers must always
///   pass `CHUNKS_PER_SEGMENT` (see `decrypt_file`) -- this is a test-only
///   seam, not a format parameter.
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if verification fails, validation fails, wrong key, corrupted file, or authentication fails
fn decrypt_file_with_segment_size(
    input_path: &str,
    output_path: Option<&str>,
    private_key_path: &str,
    passphrase: Option<String>,
    chunks_per_segment: u64,
) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Validate all paths (stdin not supported for decryption - requires seekable input)
    validate_path(input_path, true, false, "Input file")?;
    validate_path(private_key_path, true, false, "Private key")?;
    let input_meta = fs::metadata(input_path).context("Failed to read input file metadata")?;
    if !input_meta.is_file() {
        bail!(
            "Input file must be a regular file, not a directory or special file: {}",
            input_path
        );
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
            let (og, temp_path) =
                claim_output_and_temp(o, "Output file already exists or cannot be created")?;
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
    let verified =
        verify_open_file(&mut fin, input_path).context("Verification failed; aborting decrypt")?;
    println!("Verify passed. Decrypting...");

    // Read and decrypt (or, for a plain-text key, simply decode) the private key
    let composite_priv = load_private_key(private_key_path, passphrase)?;
    let (mlkem_sk, x25519_sk) = parse_private_composite_key(&composite_priv.data)?;

    let VerifiedFile { parsed, body_end } = verified;
    let header_end_pos = parsed.header_bytes.len() as u64;
    let ParsedHeader {
        header_hash,
        prefix_hash,
        ciphertext_kem,
        ephemeral_x25519_pk,
        salt,
        base_nonce,
        metadata_ciphertext,
        ..
    } = parsed;

    // Rewind the verified handle back to the start of the encrypted body --
    // verify_open_file left it past the trailer (or past the body, if
    // there's no trailer) after hashing.
    fin.seek(SeekFrom::Start(header_end_pos))
        .context("Failed to rewind verified file handle")?;

    // ML-KEM decapsulation
    // Deserialize private key (3168 bytes for ML-KEM-1024)
    let mut mlkem_sk_array: [u8; 3168] = mlkem_sk
        .data
        .as_slice()
        .try_into()
        .context("Invalid ML-KEM secret key size")?;
    let mut private_key = mlkem1024::MlKem1024PrivateKey::from(mlkem_sk_array);
    mlkem_sk_array.zeroize();

    // Deserialize ciphertext (1568 bytes)
    let ciphertext_array: [u8; 1568] = ciphertext_kem
        .as_slice()
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
    let mut x25519_sk_array: [u8; 32] = x25519_sk
        .data
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 key size"))?;
    let x25519_private = StaticSecret::from(x25519_sk_array);
    x25519_sk_array.zeroize();
    let ephemeral_public = X25519PublicKey::from(ephemeral_x25519_pk);
    let mut shared_secret_x25519 = x25519_private.diffie_hellman(&ephemeral_public);

    if shared_secret_x25519.as_bytes() == &[0u8; 32] {
        bail!(
            "X25519 key exchange failed: invalid ephemeral public key (low-order point detected)"
        );
    }

    // Combine secrets. Wrapped in SensitiveData immediately so every exit
    // path below -- including a `?` early return -- zeroizes it via
    // ZeroizeOnDrop, rather than relying on a manual `.zeroize()` call that
    // only ran on a specific success path.
    let combined_secret = combine_secrets(&kem_secret_guard, &mut shared_secret_x25519);

    // Decrypts and parses the metadata region before combined_secret is
    // moved into the body cipher provider below -- this also means a wrong
    // recipient key is detected here, before any body-chunk work begins.
    let metadata_key = derive_metadata_key(&combined_secret.data, &salt)?;
    let metadata_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&metadata_key.data));
    let metadata_aad = build_metadata_aad(&prefix_hash);
    let mut metadata_plaintext = metadata_cipher
        .decrypt(
            Nonce::from_slice(&base_nonce),
            Payload {
                msg: metadata_ciphertext.as_slice(),
                aad: &metadata_aad,
            },
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Metadata decryption failed (Integrity check failed): {:?}\n\
                Possible causes: Wrong key, corrupted file, or truncation attack.",
                e
            )
        })?;
    let decoded_metadata = decode_metadata_plaintext(&metadata_plaintext)?;
    metadata_plaintext.zeroize();

    // combined_secret moves in here -- still needed to derive each
    // segment's key lazily as the chunk loop below reaches it; zeroizes
    // whenever body_provider drops (the end of this function, on every exit
    // path).
    let mut body_provider = BodyCipherProvider::new(combined_secret, salt, chunks_per_segment);
    let decoded_metadata = Some(decoded_metadata);

    // Resolve the final output path and claim it, now that a metadata-driven
    // default (if needed) is known. An explicit -o was already claimed above.
    let (final_output_path, mut output_guard, temp_path) = match early_claim {
        Some((path, og, temp_path)) => (path, og, temp_path),
        None => {
            let embedded = decoded_metadata
                .as_ref()
                .and_then(|m| m.filename.as_deref());
            let resolved = resolve_decrypt_output(input_path, embedded)?;
            validate_path(&resolved, false, false, "Output file")?;
            let (og, temp_path) = claim_output_and_temp(
                &resolved,
                "Output file already exists or cannot be created",
            )?;
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
        let mut chunk_index: u64 = 0;

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
            let mut buffer = vec![0u8; read_target];
            let bytes_read = fill_buffer(&mut fin, &mut buffer)?;

            if bytes_read == 0 {
                break;
            }
            body_pos += bytes_read as u64;

            let chunk_type = if body_pos == body_end {
                AAD_CHUNK_TYPE_LAST
            } else {
                AAD_CHUNK_TYPE_NORMAL
            };

            let (cipher, nonce, aad) =
                body_provider.params_for(chunk_index, chunk_type, &header_hash, &base_nonce)?;
            let payload = Payload {
                msg: &buffer[..bytes_read],
                aad: aad.as_slice(),
            };

            let mut plaintext = cipher.decrypt(&nonce, payload).map_err(|e| {
                anyhow::anyhow!(
                    "Decryption failed (Integrity check failed): {:?}\n\
                    Possible causes: Wrong key, corrupted file, or truncation attack.",
                    e
                )
            })?;

            fout.write_all(&plaintext)?;
            plaintext.zeroize();

            chunk_index = chunk_index
                .checked_add(1)
                .context("Chunk counter overflow -- file too large")?;
        }

        Ok(())
    })();

    // Sync temp file contents to disk before considering decryption successful,
    // so a crash right after this call can't leave a truncated "success" output.
    let decrypt_result = decrypt_result.and_then(|_| {
        fout.sync_all()
            .context("Failed to sync decrypted temp file to disk")
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
            sync_parent_dir(&final_output_path).context(
                "Failed to sync directory after rename; decrypted output may not survive a crash",
            )?;

            // Best-effort: restore the original file's mtime/atime if the
            // metadata region carried them. Runs after both disarms (same
            // precedent as sync_parent_dir above) so it can never reintroduce
            // the "nothing fallible between rename and disarm" hazard.
            // Content correctness matters far more than timestamps, so a
            // failure here is a warning, not a decrypt failure.
            if let Some(meta) = &decoded_metadata {
                let restore_result = match (meta.mtime, meta.atime) {
                    (Some(mtime), Some(atime)) => {
                        filetime::set_file_times(&final_output_path, atime, mtime)
                    }
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

/// Checks a PQE3 file's magic bytes and header structure, then recomputes a
/// SHA-256 over the whole file (minus the trailer itself) and compares it
/// against the embedded checksum trailer. Needs no private key or
/// passphrase, so it can run unattended (e.g. in cron, right after a
/// backup) as the standalone `pqenc verify` command -- and `decrypt_file`
/// also calls this directly as a preflight before touching any key
/// material, so a corrupted file is rejected clearly and cheaply rather
/// than partway through the AEAD pass.
///
/// This is a plain, unauthenticated checksum, not cryptographic
/// authentication: it catches accidental corruption (bit rot, truncation, a
/// bad copy), not deliberate tampering -- anyone with write access to the
/// file can recompute it after modifying the file. Deliberate tampering is
/// still caught by the AEAD tags at actual decrypt time.
///
/// Takes an already-open handle rather than a path, and leaves it
/// positioned just past the trailer. `decrypt_file` relies on this: it
/// opens `fin` once, verifies it here, and then seeks the very same handle
/// back to the start of the body to decrypt -- rather than reopening the
/// path a second time, which would leave a window between the check and
/// the decrypt where the file at that path could be swapped out from under
/// it.
///
/// # Returns
/// * `Ok(VerifiedFile)` if the file is structurally valid and its checksum matches
/// * `Err` otherwise -- callers (main) translate this into a non-zero exit code
fn verify_open_file(fin: &mut File, input_path: &str) -> Result<VerifiedFile> {
    let parsed = parse_header(fin)?;
    let header_end_pos = parsed.header_bytes.len() as u64;
    let file_len = fin.metadata()?.len();
    let body_end = body_end_len(file_len, header_end_pos)?;

    println!("Structure OK: valid PQE3 header");

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
    fin.read_exact(&mut trailer)
        .context("Failed to read checksum trailer")?;

    if computed == trailer {
        println!("Checksum OK: matches embedded SHA-256 trailer");
        println!("VALID: {}", input_path);
        Ok(VerifiedFile { parsed, body_end })
    } else {
        bail!(
            "CHECKSUM MISMATCH: file may be corrupted or truncated\n  computed: {}\n  trailer:  {}",
            to_hex(&computed),
            to_hex(&trailer)
        );
    }
}

/// Standalone `pqenc verify` entry point: validates `input_path`, opens it
/// once, and runs `verify_open_file`. See that function for what's actually
/// checked; this wrapper exists because the CLI command has no further use
/// for the open handle or parsed header once verification is done.
fn verify_file(input_path: &str) -> Result<()> {
    validate_path(input_path, true, false, "Input file")?;
    let input_meta = fs::metadata(input_path).context("Failed to read input file metadata")?;
    if !input_meta.is_file() {
        bail!(
            "Input file must be a regular file, not a directory or special file: {}",
            input_path
        );
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
