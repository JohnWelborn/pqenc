mod helpers;
use helpers::{TestData, TempTestEnv, TEST_PASSWORD};
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

#[test]
fn test_full_workflow_small_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let input_data = TestData::text("Hello, post-quantum world!");
    let input_path = env.create_file("input.txt", &input_data.plaintext);
    let encrypted_path = env.file_path("encrypted.enc");
    let decrypted_path = env.file_path("decrypted.txt");

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

    // Decrypt
    env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSWORD
    ).unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, input_data.plaintext);
}

#[test]
fn test_empty_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let input_path = env.create_file("empty.txt", b"");
    let encrypted_path = env.file_path("empty.enc");
    let decrypted_path = env.file_path("empty_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Decrypt
    env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSWORD
    ).unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, b"");
}

#[test]
fn test_exactly_one_chunk() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let data = vec![0x42; 64 * 1024];
    let input_path = env.create_file("onechunk.bin", &data);
    let encrypted_path = env.file_path("onechunk.enc");
    let decrypted_path = env.file_path("onechunk_dec.bin");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Decrypt
    env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSWORD
    ).unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_wrong_password_fails() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let data = b"secret data";
    let input_path = env.create_file("secret.txt", data);
    let encrypted_path = env.file_path("secret.enc");
    let decrypted_path = env.file_path("secret_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Try to decrypt with wrong password
    let result = env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        "wrong-password"
    );

    assert!(result.is_err());
}

#[test]
fn test_file_format_has_magic_bytes() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let input_path = env.create_file("test.txt", b"test");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let encrypted = fs::read(&encrypted_path).unwrap();
    assert_eq!(&encrypted[..4], b"PQE1");
}

#[test]
fn test_large_file_multiple_chunks() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let data = TestData::random(10 * 1024 * 1024); // 10MB - multiple chunks
    let input_path = env.create_file("large.bin", &data.plaintext);
    let encrypted_path = env.file_path("large.enc");
    let decrypted_path = env.file_path("large_dec.bin");

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

    // Decrypt
    env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSWORD
    ).unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, data.plaintext);
}

/// Names of leftover atomic-write temp files (`<output>.tmp.<hex>`) in `dir`.
fn temp_artifacts(dir: &std::path::Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect()
}

#[test]
fn test_encrypt_refuses_existing_output() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let input_path = env.create_file("input.txt", b"data to encrypt");

    // Occupy the output path with content we can recognize afterwards.
    const SENTINEL: &[u8] = b"pre-existing file that must not be touched";
    let encrypted_path = env.create_file("occupied.enc", SENTINEL);

    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success(),
            "Encryption must refuse to overwrite an existing output file");

    // create_new never truncates, so the original bytes must survive intact.
    assert_eq!(fs::read(&encrypted_path).unwrap(), SENTINEL,
               "Pre-existing output file was modified");

    // The rejection must happen before any temp file is created.
    let leftovers = temp_artifacts(encrypted_path.parent().unwrap());
    assert!(leftovers.is_empty(),
            "Rejected run left temp artifacts behind: {:?}", leftovers);
}

#[test]
fn test_encrypt_success_leaves_no_temp_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let data = TestData::random(256 * 1024); // spans multiple 64KB chunks
    let input_path = env.create_file("input.bin", &data.plaintext);
    let encrypted_path = env.file_path("clean.enc");
    let decrypted_path = env.file_path("clean_dec.bin");

    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // A missing disarm() or a rename mistake would strand the temp file here,
    // silently accumulating one stale copy per backup run.
    let leftovers = temp_artifacts(encrypted_path.parent().unwrap());
    assert!(leftovers.is_empty(),
            "Successful run left temp artifacts behind: {:?}", leftovers);

    // The renamed file must still be the real, decryptable output.
    env.decrypt_file_with_password(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSWORD
    ).unwrap();
    assert_eq!(fs::read(&decrypted_path).unwrap(), data.plaintext);
}

#[cfg(unix)]
#[test]
fn test_encrypted_output_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

    let input_path = env.create_file("input.txt", b"permission check");
    let encrypted_path = env.file_path("perms.enc");

    let output = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", input_path.to_str().unwrap(),
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Encryption failed: {}",
            String::from_utf8_lossy(&output.stderr));

    // fs::rename carries the temp file's mode to the destination, so this is
    // really asserting that the temp file was created with ENCRYPT_OUTPUT_MODE.
    // 0o600 is umask-independent, which is what makes this deterministic.
    let mode = fs::metadata(&encrypted_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Encrypted output should be owner-only, got {:o}", mode);
}
