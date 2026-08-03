use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const TEST_PASSPHRASE: &str = "test-tar-passphrase";

fn generate_keys_with_passphrase(pub_path: &Path, priv_path: &Path) {
    let binary = env!("CARGO_BIN_EXE_pqenc");

    let output = Command::new(binary)
        .args([
            "generate-keys",
            "--public-key",
            pub_path.to_str().unwrap(),
            "--private-key",
            priv_path.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .expect("Failed to generate keys");

    if !output.status.success() {
        panic!(
            "Key generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_via_tar_command() {
    if Command::new("tar")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let temp_root = TempDir::new().unwrap();
    let dir_name = "data";
    let dir_path = temp_root.path().join(dir_name);
    fs::create_dir_all(&dir_path).unwrap();

    let test_content = b"hello world";
    let test_file = "file.txt";
    fs::write(dir_path.join(test_file), test_content).unwrap();

    let public_key_path = temp_root.path().join("pub.key");
    let private_key_path = temp_root.path().join("priv.key");
    generate_keys_with_passphrase(&public_key_path, &private_key_path);

    let encrypted_path = temp_root.path().join("archive.tar.gz.pqe");
    let pqenc_bin = std::env::var("CARGO_BIN_EXE_pqenc")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_pqenc").to_string());

    // Encrypt: tar czf - data | pqenc encrypt
    let mut tar = Command::new("tar")
        .args(["czf", "-", dir_name])
        .current_dir(temp_root.path())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn tar");
    let tar_stdout = tar.stdout.take().expect("Failed to capture tar stdout");

    let mut enc = Command::new(&pqenc_bin)
        .args([
            "encrypt",
            "--encrypt",
            "/dev/stdin",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .stdin(Stdio::from(tar_stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pqenc encrypt");

    let enc_status = enc.wait().expect("Failed to wait for pqenc");
    let tar_status = tar.wait().expect("Failed to wait for tar");
    assert!(tar_status.success(), "tar failed");
    assert!(enc_status.success(), "pqenc encrypt failed");

    // Verify magic bytes
    let mut magic = [0u8; 4];
    let mut file = fs::File::open(&encrypted_path).unwrap();
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"PQE3");
    drop(file);

    // Decrypt: pqenc decrypt | tar xzf -
    let extract_dir = temp_root.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();

    let decrypted_tar_path = temp_root.path().join("decrypted.tar.gz");
    let decrypt_output = Command::new(&pqenc_bin)
        .args([
            "decrypt",
            "--decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_tar_path.to_str().unwrap(),
            "--private-key",
            private_key_path.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .expect("Failed to run pqenc decrypt");

    assert!(
        decrypt_output.status.success(),
        "pqenc decrypt failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    // Extract the decrypted tar
    let untar_status = Command::new("tar")
        .args(["xzf", decrypted_tar_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");

    assert!(untar_status.success(), "tar extract failed");

    // Verify the extracted content matches the original
    let extracted_file = extract_dir.join(dir_name).join(test_file);
    let extracted_content = fs::read(&extracted_file).unwrap();
    assert_eq!(
        extracted_content, test_content,
        "Decrypted content doesn't match original"
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_via_tar_stdin_shorthand() {
    if Command::new("tar")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let temp_root = TempDir::new().unwrap();
    let dir_name = "data";
    let dir_path = temp_root.path().join(dir_name);
    fs::create_dir_all(&dir_path).unwrap();

    let test_content = b"stdin shorthand test";
    let test_file = "file.txt";
    fs::write(dir_path.join(test_file), test_content).unwrap();

    let public_key_path = temp_root.path().join("pub.key");
    let private_key_path = temp_root.path().join("priv.key");
    generate_keys_with_passphrase(&public_key_path, &private_key_path);

    let encrypted_path = temp_root.path().join("archive.tar.gz.pqe");
    let pqenc_bin = std::env::var("CARGO_BIN_EXE_pqenc")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_pqenc").to_string());

    // Encrypt using "-" as stdin shorthand instead of "/dev/stdin"
    let mut tar = Command::new("tar")
        .args(["czf", "-", dir_name])
        .current_dir(temp_root.path())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn tar");
    let tar_stdout = tar.stdout.take().expect("Failed to capture tar stdout");

    let mut enc = Command::new(&pqenc_bin)
        .args([
            "encrypt",
            "--encrypt",
            "-",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .stdin(Stdio::from(tar_stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pqenc encrypt");

    let enc_status = enc.wait().expect("Failed to wait for pqenc");
    let tar_status = tar.wait().expect("Failed to wait for tar");
    assert!(tar_status.success(), "tar failed");
    assert!(enc_status.success(), "pqenc encrypt failed");

    // Decrypt and verify
    let decrypted_tar_path = temp_root.path().join("decrypted.tar.gz");
    let decrypt_output = Command::new(&pqenc_bin)
        .args([
            "decrypt",
            "--decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_tar_path.to_str().unwrap(),
            "--private-key",
            private_key_path.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .expect("Failed to run pqenc decrypt");

    assert!(
        decrypt_output.status.success(),
        "pqenc decrypt failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    let extract_dir = temp_root.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();

    let untar_status = Command::new("tar")
        .args(["xzf", decrypted_tar_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");

    assert!(untar_status.success(), "tar extract failed");

    let extracted_content = fs::read(extract_dir.join(dir_name).join(test_file)).unwrap();
    assert_eq!(
        extracted_content, test_content,
        "Decrypted content doesn't match original"
    );
}
