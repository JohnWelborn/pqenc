mod helpers;
use helpers::{TempTestEnv, TEST_PASSPHRASE};
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

// Note: the test proving a malicious embedded filename (e.g. containing
// "..") can't cause decrypt to write outside the intended directory lives
// in src/tests.rs (tests::pqe2_format_tests::test_decrypt_rejects_traversal_in_embedded_filename),
// not here. It requires constructing ciphertext with a hostile metadata
// field value that the real `pqenc encrypt` binary can never produce (the
// embedded filename always comes from `Path::file_name()`, which never
// contains a path separator), so it can only be built from this crate's own
// internals in a unit test, not driven black-box through the compiled binary.

#[test]
fn test_truncation_attack_detected() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test data for truncation");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(["encrypt",
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
        .args(["encrypt",
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
            .args(["encrypt",
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
fn test_encrypted_file_does_not_contain_plaintext_content() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Long and distinctive enough that an accidental substring match in
    // high-entropy ciphertext is not a realistic possibility.
    let marker = b"THIS-IS-THE-PLAINTEXT-MARKER-0123456789-must-not-appear-in-ciphertext";
    let input_path = env.create_file("payload.txt", marker);
    let encrypted_path = env.file_path("payload.txt.pqe");

    let output = Command::new(pqenc_binary())
        .args(["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    let encrypted = fs::read(&encrypted_path).unwrap();
    assert!(
        !encrypted.windows(marker.len()).any(|w| w == marker),
        "encrypted output must not contain the plaintext content in the clear"
    );
}

#[test]
fn test_encrypted_file_does_not_contain_original_filename() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // The embedded-filename metadata region is AEAD-encrypted; this proves
    // it, rather than trusting that it was wired up correctly.
    let distinctive_name = "super-secret-project-codename-fizzbuzz.txt";
    let input_path = env.create_file(distinctive_name, b"unrelated content");
    let encrypted_path = env.file_path("out.pqe");

    let output = Command::new(pqenc_binary())
        .args(["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    let encrypted = fs::read(&encrypted_path).unwrap();
    let name_bytes = distinctive_name.as_bytes();
    assert!(
        !encrypted.windows(name_bytes.len()).any(|w| w == name_bytes),
        "encrypted output must not contain the original filename in the clear"
    );
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
        .args(["encrypt",
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
        .args(["encrypt",
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
