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
//! - HKDF-SHA256: Derives the AES-256 key from ML-KEM secret || X25519 secret
//! - AES-256-GCM: Authenticated encryption with additional data
//! - Context-binding AAD: Each chunk authenticated with chunk index and header hash
//! - Zeroization: Automatic clearing of sensitive data from memory
//! - Chunked encryption: 64KB chunks with unique nonces and authentication
//!
//! # File Format
//! ```text
//! [4 bytes: Magic "PQE1"]
//! [4 bytes: KEM ciphertext length]
//! [N bytes: KEM ciphertext]
//! [32 bytes: ephemeral X25519 public key]
//! [16 bytes: Salt for HKDF]
//! [12 bytes: Base nonce]
//! [Encrypted chunks with 16-byte authentication tags]
//! ```
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
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write, Seek};
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::prelude::*;

// Constants
const AES_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const MAX_KEM_CIPHERTEXT_SIZE: usize = 10000;
const MAGIC: &[u8] = b"PQE1";
const AAD_CHUNK_TYPE_NORMAL: u8 = 0x00;
const AAD_CHUNK_TYPE_LAST: u8 = 0x01;

// X25519 and hybrid constants
const X25519_PUBLIC_KEY_SIZE: usize = 32;
const X25519_PRIVATE_KEY_SIZE: usize = 32;
const SHARED_SECRET_SIZE: usize = 64; // KEM (32) + X25519 (32)

// Password-based encryption constants
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
"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        private_key: String,
    },
    Encrypt {
        #[arg(long = "encrypt")]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        public_key: String,
    },
    Decrypt {
        #[arg(long = "decrypt", help = "Input file to decrypt (must be a regular file, not stdin or a pipe)")]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        private_key: String,
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
/// in temporary files if decryption fails or panics.
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

/// Encode bytes as PEM with custom headers
fn pem_encode(der_bytes: &[u8], begin: &str, end: &str) -> String {
    let b64 = BASE64_STANDARD.encode(der_bytes);
    let lines: Vec<String> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
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

/// Derive encryption key from password using Argon2id
fn derive_key_from_password(password: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    use argon2::{Argon2, Algorithm, Version, Params};

    if password.is_empty() {
        bail!("Password cannot be empty");
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
    argon2.hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 failed: {}", e))?;

    Ok(SensitiveData::new(key))
}

/// Encrypt composite private key with password
fn encrypt_private_key(composite_key: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    use rand::Rng;

    let salt: [u8; ARGON2_SALT_SIZE] = rand::rng().random();
    let key = derive_key_from_password(password, &salt)?;

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

/// Decrypt private key with password
fn decrypt_private_key(encrypted_blob: &[u8], password: &[u8]) -> Result<SensitiveData> {
    let min_size = ARGON2_SALT_SIZE + PBE_NONCE_SIZE + 1 + 16; // +16 for GCM tag
    if encrypted_blob.len() < min_size {
        bail!("Encrypted data too short");
    }

    let salt = &encrypted_blob[..ARGON2_SALT_SIZE];
    let nonce = &encrypted_blob[ARGON2_SALT_SIZE..ARGON2_SALT_SIZE + PBE_NONCE_SIZE];
    let ciphertext = &encrypted_blob[ARGON2_SALT_SIZE + PBE_NONCE_SIZE..];

    let key = derive_key_from_password(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.data));

    let plaintext = cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: ciphertext,
            aad: b"pqenc-private-key-v1",
        }
    ).map_err(|_| anyhow::anyhow!("Decryption failed - wrong password or corrupted key"))?;

    Ok(SensitiveData::new(plaintext))
}

/// Parse composite public key: [4-byte len][ML-KEM pk][X25519 pk(32)]
fn parse_public_composite_key(data: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if data.len() < 4 + X25519_PUBLIC_KEY_SIZE {
        bail!("Public key data too short");
    }

    let kem_len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if kem_len == 0 || kem_len > 8000 {
        bail!("Invalid ML-KEM public key length");
    }

    let expected_len = 4 + kem_len + X25519_PUBLIC_KEY_SIZE;
    if data.len() != expected_len {
        bail!("Invalid composite public key size");
    }

    let mlkem_pk = data[4..4 + kem_len].to_vec();
    let x25519_pk: [u8; 32] = data[4 + kem_len..].try_into().unwrap();

    Ok((mlkem_pk, x25519_pk))
}

/// Parse composite private key: [4-byte len][ML-KEM sk][X25519 sk(32)]
fn parse_private_composite_key(data: &[u8]) -> Result<(SensitiveData, SensitiveData)> {
    if data.len() < 4 + X25519_PRIVATE_KEY_SIZE {
        bail!("Private key data too short");
    }

    let kem_len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if kem_len == 0 || kem_len > 10000 {
        bail!("Invalid ML-KEM private key length");
    }

    let expected_len = 4 + kem_len + X25519_PRIVATE_KEY_SIZE;
    if data.len() != expected_len {
        bail!("Invalid composite private key size");
    }

    let mlkem_sk = SensitiveData::new(data[4..4 + kem_len].to_vec());
    let x25519_sk = SensitiveData::new(data[4 + kem_len..].to_vec());

    Ok((mlkem_sk, x25519_sk))
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
        Commands::GenerateKeys { public_key, private_key } => {
            generate_keys(&public_key, &private_key)?;
        }
        Commands::Encrypt { input, output, public_key } => {
            encrypt_file(&input, &output, &public_key)?;
        }
        Commands::Decrypt { input, output, private_key } => {
            decrypt_file(&input, &output, &private_key)?;
        }
    }

    Ok(())
}

/// Generates a new ML-KEM-1024 + X25519 hybrid keypair and saves to files.
///
/// Creates a hybrid post-quantum key pair using both ML-KEM-1024 and X25519,
/// encodes them in PEM format, and encrypts the private key with a password.
/// On Unix systems, sets private key permissions to 0o600 for security.
///
/// # Arguments
/// * `public_key_path` - Path where public key will be saved
/// * `private_key_path` - Path where private key will be saved (encrypted)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if files already exist, paths are invalid, or key generation fails
fn generate_keys(public_key_path: &str, private_key_path: &str) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    // Validate paths
    validate_path(public_key_path, false, false, "Public key")?;
    validate_path(private_key_path, false, false, "Private key")?;

    // Generate ML-KEM keypair
    let mut key_gen_randomness = [0u8; 64];
    rand::rng().fill_bytes(&mut key_gen_randomness);
    let key_pair = mlkem1024::generate_key_pair(key_gen_randomness);
    let mlkem_public = key_pair.public_key();
    let mlkem_secret = key_pair.private_key();
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

    // Prompt for password
    eprintln!("Enter password for private key:");
    let mut password1 = rpassword::read_password()?;
    eprintln!("Confirm password:");
    let mut password2 = rpassword::read_password()?;

    if password1 != password2 {
        password1.zeroize();
        password2.zeroize();
        bail!("Passwords do not match");
    }
    if password1.is_empty() {
        password1.zeroize();
        password2.zeroize();
        bail!("Password cannot be empty");
    }
    if password1.len() < 12 {
        eprintln!("Warning: Password shorter than 12 characters may be weak");
    }

    // Encrypt private key
    let encrypted_priv = {
        let result = encrypt_private_key(&composite_priv, password1.as_bytes());
        password1.zeroize();
        password2.zeroize();
        result?
    };

    // Zeroize sensitive data
    drop(key_pair);
    drop(x25519_secret);
    composite_priv.zeroize();

    // Save as PEM
    let pem_pub = pem_encode(&composite_pub, PEM_PUB_BEGIN, PEM_PUB_END);
    let pem_priv = pem_encode(&encrypted_priv, PEM_PRIV_ENC_BEGIN, PEM_PRIV_ENC_END);

    // Use create_new to atomically prevent TOCTOU/symlink attacks
    let mut pub_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(public_key_path)?;
    pub_file.write_all(pem_pub.as_bytes())?;

    // Write private key with atomic 0600 permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(private_key_path)?;
        file.write_all(pem_priv.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(private_key_path)?;
        file.write_all(pem_priv.as_bytes())?;
        let mut perms = file.metadata()?.permissions();
        perms.set_readonly(false);
        file.set_permissions(perms)?;
    }

    println!("Key pair generated successfully");
    println!("  Public key:  {}", public_key_path);
    println!("  Private key: {}", private_key_path);
    println!("  Algorithm:   ML-KEM-1024 + X25519 (hybrid)");
    println!("  Private key is password-encrypted");

    Ok(())
}

/// Derives an AES-256 key from a combined secret using HKDF-SHA256.
///
/// Uses HKDF with the provided salt and info string "pqenc-hybrid-aes-key"
/// to derive a 32-byte key suitable for AES-256-GCM.
/// The combined secret should be 64 bytes (32 from ML-KEM + 32 from X25519).
fn derive_aes_key(combined_secret: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    if combined_secret.len() != SHARED_SECRET_SIZE {
        bail!("Combined secret must be {} bytes", SHARED_SECRET_SIZE);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), combined_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(b"pqenc-hybrid-aes-key", &mut okm)
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

/// Encrypts a file using ML-KEM-1024 + X25519 + AES-256-GCM.
///
/// Performs hybrid post-quantum encryption:
/// 1. Encapsulates a shared secret using the recipient's ML-KEM-1024 public key
/// 2. Performs X25519 key exchange with ephemeral key
/// 3. Combines both secrets and derives an AES-256 key using HKDF-SHA256
/// 4. Encrypts the file in 64KB chunks using AES-256-GCM with unique nonces
/// 5. Writes encrypted output with header containing KEM ciphertext, X25519 public key, salt, and base nonce
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
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    // Zeroize combined secret
    combined_secret.zeroize();

    let mut fin = open_input(input_path)?;
    let input_size = if is_stdin {
        None
    } else {
        Some(File::open(input_path)?.metadata()?.len())
    };

    // Use create_new to atomically prevent TOCTOU/symlink attacks
    let mut fout = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .context("Failed to create output file (already exists or permission denied)")?;

    // Build header and compute hash for AAD
    let kem_ct_len = ciphertext.as_slice().len() as u32;
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&kem_ct_len.to_be_bytes());
    header.extend_from_slice(ciphertext.as_slice());
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    // Compute header hash for AAD binding
    use sha2::Digest;
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    // Write header to file
    fout.write_all(&header)?;


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

    println!("File encrypted successfully");
    if let Some(size) = input_size {
        println!("  Input:  {} ({} bytes)", input_path, size);
    } else {
        println!("  Input:  {} (stdin)", input_path);
    }
    println!("  Output: {}", output_path);
    println!("  Using:  ML-KEM-1024 + X25519 + AES-256-GCM");

    Ok(())
}

/// Decrypts a file encrypted with ML-KEM-1024 + X25519 + AES-256-GCM.
///
/// Performs hybrid post-quantum decryption:
/// 1. Reads and validates file header (magic bytes, KEM ciphertext, X25519 public key, salt, nonce)
/// 2. Prompts for password and decrypts the password-protected private key
/// 3. Decapsulates the shared secret using the recipient's ML-KEM-1024 private key
/// 4. Performs X25519 key exchange with ephemeral public key
/// 5. Combines secrets and derives the AES-256 key using HKDF-SHA256
/// 6. Decrypts chunks using AES-256-GCM, verifying authentication tags
/// 7. Deletes partial output and returns error if integrity check fails
///
/// # Arguments
/// * `input_path` - Path to encrypted file
/// * `output_path` - Path where decrypted file will be written
/// * `private_key_path` - Path to password-encrypted hybrid private key
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if validation fails, wrong key, corrupted file, or authentication fails
fn decrypt_file(input_path: &str, output_path: &str, private_key_path: &str) -> Result<()> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use rand::Rng;

    // Validate all paths (stdin not supported for decryption - requires seekable input)
    validate_path(input_path, true, false, "Input file")?;
    validate_path(output_path, false, false, "Output file")?;
    validate_path(private_key_path, true, false, "Private key")?;
    let input_meta = fs::metadata(input_path)
        .context("Failed to read input file metadata")?;
    if !input_meta.is_file() {
        bail!("Input file must be a regular file, not a directory or special file: {}", input_path);
    }

    // Generate temporary file path for atomic write
    let temp_path = format!("{}.tmp.{:x}", output_path, rand::rng().random::<u64>());
    let mut temp_guard = TempFileGuard::new(temp_path);

    // Read and decrypt private key
    let pem_text = fs::read_to_string(private_key_path).context("Failed to read private key")?;
    let encrypted_blob = pem_decode(&pem_text, PEM_PRIV_ENC_BEGIN, PEM_PRIV_ENC_END)?;

    eprintln!("Enter private key password:");
    let mut password = rpassword::read_password()?;
    let composite_priv = {
        let result = decrypt_private_key(&encrypted_blob, password.as_bytes());
        password.zeroize();
        result?
    };
    let (mlkem_sk, x25519_sk) = parse_private_composite_key(&composite_priv.data)?;

    let mut fin = File::open(input_path).context("Failed to open input file")?;

    // Read and parse header
    let mut magic = [0u8; 4];
    fin.read_exact(&mut magic)?;
    if magic != MAGIC {
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

    // Compute header hash for AAD binding
    use sha2::Digest;
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    // Validate file contains encrypted data beyond the header
    let header_end_pos = fin.stream_position()?;
    let file_len = fin.metadata()?.len();
    if file_len < header_end_pos + TAG_SIZE as u64 {
        bail!("Invalid ciphertext: file too short. This may indicate file truncation or corruption.");
    }

    // ML-KEM decapsulation
    // Deserialize private key (3168 bytes for ML-KEM-1024)
    let mut mlkem_sk_array: [u8; 3168] = mlkem_sk.data.as_slice()
        .try_into()
        .context("Invalid ML-KEM secret key size")?;
    let private_key = mlkem1024::MlKem1024PrivateKey::from(mlkem_sk_array);
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

    // Zeroize combined secret
    combined_secret.zeroize();

    // Create temporary output file with restrictive permissions (0o600 on Unix)
    #[cfg(unix)]
    let mut fout = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp_guard.path())
            .context("Failed to create temporary output file")?
    };

    #[cfg(not(unix))]
    let mut fout = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_guard.path())
        .context("Failed to create temporary output file")?;

    // Perform decryption - any error will trigger cleanup of temp file
    let decrypt_result = (|| -> Result<()> {
        let encrypted_chunk_size = CHUNK_SIZE + TAG_SIZE;
        let mut chunk_index = 0;

        let file_len = fin.metadata()
            .context("Failed to get file metadata - decryption requires a seekable input file, not stdin or a pipe")?
            .len();

        loop {
            // Read up to encrypted_chunk_size.
            // We loop to ensure we fill the buffer if possible, though for local files read() usually suffices.
            let mut buffer = vec![0u8; encrypted_chunk_size];
            let mut bytes_read = 0;
            while bytes_read < encrypted_chunk_size {
                let n = fin.read(&mut buffer[bytes_read..])?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }


            if bytes_read == 0 {
                break;
            }

            let current_pos = fin.stream_position()?;
            let chunk_type = if current_pos == file_len { AAD_CHUNK_TYPE_LAST } else { AAD_CHUNK_TYPE_NORMAL };
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

    // Ensure file is closed before rename/delete
    drop(fout);

    // Handle result: atomic rename on success, cleanup on error
    match decrypt_result {
        Ok(_) => {
            // Final check before rename to minimize TOCTOU window
            if std::path::Path::new(output_path).exists() {
                // Guard will clean up temp file automatically
                bail!("Output file already exists: {}", output_path);
            }

            // Disarm guard before rename to prevent deletion of successfully decrypted file
            let temp_path = temp_guard.path().to_string();
            temp_guard.disarm();

            fs::rename(&temp_path, output_path)
                .context("Failed to move decrypted file to final destination")?;
            println!("File decrypted successfully: {}", output_path);
            Ok(())
        }
        Err(e) => {
            // Guard will automatically clean up temp file on drop
            Err(e)
        }
    }
}


#[cfg(test)]
mod tests;
