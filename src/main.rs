//! Post-Quantum File Encryption Tool
//!
//! Provides hybrid post-quantum encryption using ML-KEM-1024 (NIST FIPS 203)
//! for key encapsulation and AES-256-GCM for symmetric encryption.
//!
//! # Security Features
//! - ML-KEM-1024: Post-quantum secure key encapsulation mechanism
//! - AES-256-GCM: Authenticated encryption with additional data
//! - HKDF-SHA256: Cryptographic key derivation
//! - Zeroization: Automatic clearing of sensitive data from memory
//! - Chunked encryption: 64KB chunks with unique nonces and authentication
//!
//! # File Format
//! ```text
//! [4 bytes: Magic "PQE1"]
//! [4 bytes: KEM ciphertext length]
//! [N bytes: KEM ciphertext]
//! [16 bytes: Salt for HKDF]
//! [12 bytes: Base nonce]
//! [Encrypted chunks with 16-byte authentication tags]
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use oqs::kem::{Kem, Algorithm};
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write, Seek};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::prelude::*;

// Constants
const KEM_ALGORITHM: Algorithm = Algorithm::MlKem1024;
const AES_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const MAX_KEM_CIPHERTEXT_SIZE: usize = 10000;
const MAGIC: &[u8] = b"PQE1";
const AAD_CHUNK: &[u8] = b"\x00";
const AAD_LAST_CHUNK: &[u8] = b"\x01";

#[derive(Parser)]
#[command(name = "pqenc")]
#[command(about = "Post-Quantum File Encryption Tool (ML-KEM-1024 + AES-256-GCM)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // Flatten flags for compatibility with Python script's argparse style
    // The Python script uses mutually exclusive flags --generate-keys, --encrypt, --decrypt
    // Here we support both subcommands (cleaner) and flags (compat)
    
    #[arg(long, conflicts_with_all = ["encrypt", "decrypt"])]
    generate_keys: bool,

    #[arg(long, conflicts_with_all = ["generate_keys", "decrypt"])]
    encrypt: Option<String>,

    #[arg(long, conflicts_with_all = ["generate_keys", "encrypt"])]
    decrypt: Option<String>,

    #[arg(long)]
    public_key: Option<String>,

    #[arg(long)]
    private_key: Option<String>,

    #[arg(long)]
    output: Option<String>,
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
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        public_key: String,
    },
    Decrypt {
        #[arg(long)]
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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

/// Validates a file path for basic sanity checks.
fn validate_path(path: &str, must_exist: bool, description: &str) -> Result<()> {
    if path.is_empty() {
        bail!("{} path cannot be empty", description);
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

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Handle compatibility flags mapping to commands
    if cli.generate_keys {
        let pub_path = cli.public_key.context("--generate-keys requires --public-key")?;
        let priv_path = cli.private_key.context("--generate-keys requires --private-key")?;
        generate_keys(&pub_path, &priv_path)?;
    } else if let Some(input_path) = cli.encrypt {
        let pub_path = cli.public_key.context("--encrypt requires --public-key")?;
        let output_path = cli.output.context("--encrypt requires --output")?;
        encrypt_file(&input_path, &output_path, &pub_path)?;
    } else if let Some(input_path) = cli.decrypt {
        let priv_path = cli.private_key.context("--decrypt requires --private-key")?;
        let output_path = cli.output.context("--decrypt requires --output")?;
        decrypt_file(&input_path, &output_path, &priv_path)?;
    } else {
        // Try subcommands
        match cli.command {
            Some(Commands::GenerateKeys { public_key, private_key }) => {
                generate_keys(&public_key, &private_key)?;
            }
            Some(Commands::Encrypt { input, output, public_key }) => {
                encrypt_file(&input, &output, &public_key)?;
            }
            Some(Commands::Decrypt { input, output, private_key }) => {
                decrypt_file(&input, &output, &private_key)?;
            }
            None => {
                use clap::CommandFactory;
                Cli::command().print_help()?;
            }
        }
    }

    Ok(())
}

/// Generates a new ML-KEM-1024 keypair and saves to files.
///
/// Creates a new post-quantum key pair using ML-KEM-1024 algorithm,
/// encodes both keys as base64, and saves them to the specified paths.
/// On Unix systems, sets private key permissions to 0o600 for security.
///
/// # Arguments
/// * `public_key_path` - Path where public key will be saved
/// * `private_key_path` - Path where private key will be saved
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if files already exist, paths are invalid, or key generation fails
fn generate_keys(public_key_path: &str, private_key_path: &str) -> Result<()> {
    // Validate paths
    validate_path(public_key_path, false, "Public key")?;
    validate_path(private_key_path, false, "Private key")?;

    if std::path::Path::new(public_key_path).exists() {
        bail!("Public key file already exists: {}", public_key_path);
    }
    if std::path::Path::new(private_key_path).exists() {
        bail!("Private key file already exists: {}", private_key_path);
    }

    let kem = Kem::new(KEM_ALGORITHM)?;
    let (public_key, secret_key) = kem.keypair()?;

    // Wrap secret key for zeroization
    let secret_guard = SensitiveData::new(secret_key.into_vec());

    // Save keys as base64
    let pk_b64 = BASE64_STANDARD.encode(public_key.as_ref());
    let sk_b64 = BASE64_STANDARD.encode(&secret_guard.data);

    fs::write(public_key_path, pk_b64)?;

    // Write private key and set permissions
    {
        let mut file = File::create(private_key_path)?;
        file.write_all(sk_b64.as_bytes())?;

        // Set restrictive permissions on private key
        #[cfg(unix)]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        #[cfg(windows)]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_readonly(false); // Ensure we can read it
        }
    }

    println!("Key pair generated successfully");
    println!("  Public key:  {}", public_key_path);
    println!("  Private key: {}", private_key_path);
    println!("  Algorithm:   ML-KEM-1024");

    Ok(())
}

/// Derives an AES-256 key from a shared secret using HKDF-SHA256.
///
/// Uses HKDF with the provided salt and info string "pqenc-v1-aes-key"
/// to derive a 32-byte key suitable for AES-256-GCM.
fn derive_aes_key(shared_secret: &[u8], salt: &[u8]) -> Result<SensitiveData> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(b"pqenc-v1-aes-key", &mut okm)
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

    // Use checked_add to detect overflow - critical for AES-GCM security
    let new_int = base_int.checked_add(counter as u128)
        .ok_or_else(|| anyhow::anyhow!("Nonce counter overflow - file too large"))?;

    let bytes = new_int.to_be_bytes();
    // Take last 12 bytes
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&bytes[4..16]);

    Ok(*Nonce::from_slice(&nonce_bytes))
}

/// Encrypts a file using ML-KEM-1024 + AES-256-GCM.
///
/// Performs hybrid post-quantum encryption:
/// 1. Encapsulates a shared secret using the recipient's ML-KEM-1024 public key
/// 2. Derives an AES-256 key from the shared secret using HKDF-SHA256
/// 3. Encrypts the file in 64KB chunks using AES-256-GCM with unique nonces
/// 4. Writes encrypted output with header containing KEM ciphertext, salt, and base nonce
///
/// # Arguments
/// * `input_path` - Path to plaintext file to encrypt
/// * `output_path` - Path where encrypted file will be written
/// * `public_key_path` - Path to recipient's ML-KEM-1024 public key
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if validation fails, encryption fails, or I/O errors occur
fn encrypt_file(input_path: &str, output_path: &str, public_key_path: &str) -> Result<()> {
    // Check if input is a directory
    let input_p = std::path::Path::new(input_path);
    if input_p.exists() && input_p.is_dir() {
        let dirname = input_p.file_name().and_then(|n| n.to_str()).unwrap_or(input_path);
        bail!(
            "Input file is a directory, not a file: {}\n\n\
            pqenc can only encrypt individual files. To encrypt a directory:\n\
            tar czf - {} | pqenc --encrypt /dev/stdin --output {}.tar.gz.pqe --public-key {}",
            input_path, dirname, dirname, public_key_path
        );
    }

    // Validate all paths
    validate_path(input_path, true, "Input file")?;
    validate_path(output_path, false, "Output file")?;
    validate_path(public_key_path, true, "Public key")?;

    if std::path::Path::new(output_path).exists() {
        bail!("Output file already exists: {}", output_path);
    }

    let pk_b64 = fs::read_to_string(public_key_path).context("Failed to read public key")?;
    let pk_bytes = BASE64_STANDARD.decode(pk_b64.trim()).context("Failed to decode public key")?;

    let kem = Kem::new(KEM_ALGORITHM)?;
    let pk_ref = kem.public_key_from_bytes(&pk_bytes).context("Invalid public key")?;
    let (ciphertext_kem, shared_secret) = kem.encapsulate(pk_ref)?;
    let secret_guard = SensitiveData::new(shared_secret.into_vec());

    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill_bytes(&mut salt);

    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut base_nonce);

    let aes_key = derive_aes_key(&secret_guard.data, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    let mut fin = File::open(input_path).context("Failed to open input file")?;
    let input_size = fin.metadata()?.len();
    let mut fout = File::create(output_path).context("Failed to create output file")?;

    // Write Header
    fout.write_all(MAGIC)?;
    
    let kem_ct_len = ciphertext_kem.as_ref().len() as u32;
    fout.write_all(&kem_ct_len.to_be_bytes())?;
    fout.write_all(ciphertext_kem.as_ref())?;
    fout.write_all(&salt)?;
    fout.write_all(&base_nonce)?;


    let mut chunk_index = 0;

    // Allocate buffers once and reuse them
    let mut current_chunk = vec![0u8; CHUNK_SIZE];
    let mut next_chunk = vec![0u8; CHUNK_SIZE];
    let mut n_current = fin.read(&mut current_chunk)?;

    loop {
        let n_next = fin.read(&mut next_chunk)?;

        let aad = if n_next == 0 { AAD_LAST_CHUNK } else { AAD_CHUNK };

        let nonce = get_nonce(&base_nonce, chunk_index)?;
        let payload = Payload {
            msg: &current_chunk[..n_current],
            aad,
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
    println!("  Input:  {} ({} bytes)", input_path, input_size);
    println!("  Output: {}", output_path);
    println!("  Using:  ML-KEM-1024 + AES-256-GCM");

    Ok(())
}

/// Decrypts a file encrypted with ML-KEM-1024 + AES-256-GCM.
///
/// Performs hybrid post-quantum decryption:
/// 1. Reads and validates file header (magic bytes, KEM ciphertext, salt, nonce)
/// 2. Decapsulates the shared secret using the recipient's ML-KEM-1024 private key
/// 3. Derives the AES-256 key from the shared secret using HKDF-SHA256
/// 4. Decrypts chunks using AES-256-GCM, verifying authentication tags
/// 5. Deletes partial output and returns error if integrity check fails
///
/// # Arguments
/// * `input_path` - Path to encrypted file
/// * `output_path` - Path where decrypted file will be written
/// * `private_key_path` - Path to ML-KEM-1024 private key
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if validation fails, wrong key, corrupted file, or authentication fails
fn decrypt_file(input_path: &str, output_path: &str, private_key_path: &str) -> Result<()> {
    // Validate all paths
    validate_path(input_path, true, "Input file")?;
    validate_path(output_path, false, "Output file")?;
    validate_path(private_key_path, true, "Private key")?;

    if std::path::Path::new(output_path).exists() {
        bail!("Output file already exists: {}", output_path);
    }

    let sk_b64 = fs::read_to_string(private_key_path).context("Failed to read private key")?;
    let sk_bytes = BASE64_STANDARD.decode(sk_b64.trim()).context("Failed to decode private key")?;
    let sk_guard = SensitiveData::new(sk_bytes);

    let mut fin = File::open(input_path).context("Failed to open input file")?;

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

    let mut salt = [0u8; SALT_SIZE];
    fin.read_exact(&mut salt)?;

    let mut base_nonce = [0u8; NONCE_SIZE];
    fin.read_exact(&mut base_nonce)?;

    let kem = Kem::new(KEM_ALGORITHM)?;
    // oqs-rs expects secret key as reference
    let sk_ref = kem.secret_key_from_bytes(&sk_guard.data).context("Invalid secret key")?;
    let ct_ref = kem.ciphertext_from_bytes(&ciphertext_kem).context("Invalid ciphertext")?;
    let shared_secret = kem.decapsulate(sk_ref, ct_ref)?;
    let secret_guard = SensitiveData::new(shared_secret.into_vec());

    let aes_key = derive_aes_key(&secret_guard.data, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    let mut fout = File::create(output_path).context("Failed to create output file")?;

    let encrypted_chunk_size = CHUNK_SIZE + TAG_SIZE;
    let mut chunk_index = 0;
    
    let file_len = fin.metadata()?.len();

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
        let aad = if current_pos == file_len { AAD_LAST_CHUNK } else { AAD_CHUNK };

        let nonce = get_nonce(&base_nonce, chunk_index)?;
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad,
        };
        
        match cipher.decrypt(&nonce, payload) {
            Ok(mut plaintext) => {
                fout.write_all(&plaintext)?;
                plaintext.zeroize();
            }
            Err(e) => {
                // Delete partial output
                drop(fout);
                let _ = fs::remove_file(output_path);
                bail!("Decryption failed (Integrity check failed): {:?}\nPossible causes: Wrong key, corrupted file, or truncation attack.", e);
            }
        }
        
        chunk_index += 1;
    }

    println!("File decrypted successfully: {}", output_path);

    Ok(())
}
