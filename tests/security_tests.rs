mod helpers;
use helpers::{TempTestEnv, TEST_PASSPHRASE};
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

#[test]
fn test_truncation_attack_detected() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test data for truncation");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // Truncate encrypted file
    let mut encrypted = fs::read(&encrypted_path).unwrap();
    let original_len = encrypted.len();
    encrypted.truncate(original_len - 100);
    fs::write(&encrypted_path, encrypted).unwrap();

    // Try to decrypt - should fail
    let result = env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("out.txt").to_str().unwrap(),
        TEST_PASSPHRASE
    );

    assert!(result.is_err(), "Truncation attack should be detected");
}

#[test]
fn test_bit_flip_detected() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test data for bit flip");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // Flip a bit in the middle of the ciphertext
    let mut encrypted = fs::read(&encrypted_path).unwrap();
    let pos = encrypted.len() / 2;
    encrypted[pos] ^= 0x01;
    fs::write(&encrypted_path, encrypted).unwrap();

    // Try to decrypt - should fail
    let result = env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("out.txt").to_str().unwrap(),
        TEST_PASSPHRASE
    );

    assert!(result.is_err(), "Bit flip attack should be detected");
}

#[test]
fn test_encryption_is_nondeterministic() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"same data");
    let enc1_path = env.file_path("enc1.enc");
    let enc2_path = env.file_path("enc2.enc");

    // Encrypt twice with same data
    for enc_path in [&enc1_path, &enc2_path] {
        let output = Command::new(pqenc_binary())
            .args(&["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", enc_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Encryption failed: {}",
                String::from_utf8_lossy(&output.stderr));
    }

    let enc1 = fs::read(&enc1_path).unwrap();
    let enc2 = fs::read(&enc2_path).unwrap();

    assert_ne!(enc1, enc2, "Encryption should be non-deterministic");
}

#[test]
fn test_invalid_magic_bytes_rejected() {
    let env = TempTestEnv::new();
    env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Create file with invalid magic bytes
    let mut bad_data = b"XXX1".to_vec();
    bad_data.extend_from_slice(&[0u8; 2000]); // Minimum plausible size

    let bad_path = env.create_file("bad.enc", &bad_data);
    let out_path = env.file_path("out.txt");

    let result = env.decrypt_file_with_passphrase(
        bad_path.to_str().unwrap(),
        out_path.to_str().unwrap(),
        TEST_PASSPHRASE
    );

    assert!(result.is_err(), "Invalid magic bytes should be rejected");
}

#[test]
fn test_header_tampering_detected() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test data");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // Tamper with header (after magic bytes but before ciphertext)
    let mut encrypted = fs::read(&encrypted_path).unwrap();
    if encrypted.len() > 100 {
        encrypted[50] ^= 0xFF; // Flip bits in the header area
        fs::write(&encrypted_path, encrypted).unwrap();
    }

    // Try to decrypt - should fail
    let result = env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("out.txt").to_str().unwrap(),
        TEST_PASSPHRASE
    );

    assert!(result.is_err(), "Header tampering should be detected");
}

#[test]
fn test_ciphertext_tampering_detected() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test data for ciphertext tampering");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // Tamper with ciphertext near the end
    let mut encrypted = fs::read(&encrypted_path).unwrap();
    let pos = encrypted.len() - 50; // Near the end but not in the tag
    encrypted[pos] ^= 0xFF;
    fs::write(&encrypted_path, encrypted).unwrap();

    // Try to decrypt - should fail due to GCM authentication
    let result = env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("out.txt").to_str().unwrap(),
        TEST_PASSPHRASE
    );

    assert!(result.is_err(), "Ciphertext tampering should be detected");
}
