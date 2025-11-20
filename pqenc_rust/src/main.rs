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

fn generate_keys(public_key_path: &str, private_key_path: &str) -> Result<()> {
    if std::path::Path::new(public_key_path).exists() {
        bail!("Public key file already exists: {}", public_key_path);
    }
    if std::path::Path::new(private_key_path).exists() {
        bail!("Private key file already exists: {}", private_key_path);
    }

    let kem = Kem::new(KEM_ALGORITHM)?;
    let (public_key, secret_key) = kem.keypair()?;
    
    // Wrap secret key for zeroization
    let _secret_guard = SensitiveData::new(secret_key.into_vec());

    // Save keys as base64
    let pk_b64 = BASE64_STANDARD.encode(public_key.as_ref());
    let sk_b64 = BASE64_STANDARD.encode(&_secret_guard.data);

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

fn derive_aes_key(shared_secret: &[u8], salt: &[u8]) -> SensitiveData {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; AES_KEY_SIZE];
    hkdf.expand(b"pqenc-v1-aes-key", &mut okm).expect("HKDF expand failed");
    SensitiveData::new(okm)
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

fn encrypt_file(input_path: &str, output_path: &str, public_key_path: &str) -> Result<()> {
    if std::path::Path::new(output_path).exists() {
        bail!("Output file already exists: {}", output_path);
    }

    let pk_b64 = fs::read_to_string(public_key_path).context("Failed to read public key")?;
    let pk_bytes = BASE64_STANDARD.decode(pk_b64.trim()).context("Failed to decode public key")?;

    let kem = Kem::new(KEM_ALGORITHM)?;
    let pk_ref = kem.public_key_from_bytes(&pk_bytes).context("Invalid public key")?;
    let (ciphertext_kem, shared_secret) = kem.encapsulate(pk_ref)?;
    let _secret_guard = SensitiveData::new(shared_secret.into_vec());

    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut base_nonce);

    let aes_key = derive_aes_key(&_secret_guard.data, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key.data);
    let cipher = Aes256Gcm::new(key);

    let mut fin = File::open(input_path).context("Failed to open input file")?;
    let mut fout = File::create(output_path).context("Failed to create output file")?;

    // Write Header
    fout.write_all(MAGIC)?;
    
    let kem_ct_len = ciphertext_kem.as_ref().len() as u32;
    fout.write_all(&kem_ct_len.to_be_bytes())?;
    fout.write_all(ciphertext_kem.as_ref())?;
    fout.write_all(&salt)?;
    fout.write_all(&base_nonce)?;


    let mut chunk_index = 0;


    
    let mut current_chunk = vec![0u8; CHUNK_SIZE];
    let mut n_current = fin.read(&mut current_chunk)?;
    

    
    loop {
        let mut next_chunk = vec![0u8; CHUNK_SIZE];
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
        
        // Zeroize current chunk
        current_chunk.zeroize();
        
        chunk_index += 1;
        
        if n_next == 0 {
            break;
        }
        
        current_chunk = next_chunk;
        n_current = n_next;
    }

    let input_size = fs::metadata(input_path)?.len();
    println!("File encrypted successfully");
    println!("  Input:  {} ({} bytes)", input_path, input_size);
    println!("  Output: {}", output_path);
    println!("  Using:  ML-KEM-1024 + AES-256-GCM");

    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, private_key_path: &str) -> Result<()> {
    if std::path::Path::new(output_path).exists() {
        bail!("Output file already exists: {}", output_path);
    }

    let sk_b64 = fs::read_to_string(private_key_path).context("Failed to read private key")?;
    let sk_bytes = BASE64_STANDARD.decode(sk_b64.trim()).context("Failed to decode private key")?;
    let _sk_guard = SensitiveData::new(sk_bytes);

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
    let sk_ref = kem.secret_key_from_bytes(&_sk_guard.data).context("Invalid secret key")?;
    let ct_ref = kem.ciphertext_from_bytes(&ciphertext_kem).context("Invalid ciphertext")?;
    let shared_secret = kem.decapsulate(sk_ref, ct_ref)?;
    let _secret_guard = SensitiveData::new(shared_secret.into_vec());

    let aes_key = derive_aes_key(&_secret_guard.data, &salt);
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
