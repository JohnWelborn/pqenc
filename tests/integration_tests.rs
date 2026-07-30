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

/// Regression test for partial output on interrupted encryption.
///
/// Kills pqenc mid-stream and asserts nothing resembling a finished backup was
/// left at the output path. Against the pre-atomicity implementation, which
/// streamed the header and chunks straight to `output_path`, this fails.
///
/// stdin is deliberately never closed, so the child cannot reach EOF and finish
/// on its own no matter how fast it encrypts — that is what keeps the timing
/// non-flaky. The writer thread stops when the kill breaks the pipe.
#[cfg(unix)]
#[test]
fn test_encrypt_killed_midstream_leaves_no_partial_output() {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);
    let encrypted_path = env.file_path("interrupted.enc");
    let dir = encrypted_path.parent().unwrap().to_path_buf();

    let mut child = Command::new(pqenc_binary())
        .args(&["encrypt",
            "--encrypt", "-",
            "--output", encrypted_path.to_str().unwrap(),
            "--public-key", pub_key.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let block = vec![0xABu8; 64 * 1024];
        // Feed until the child dies and the pipe breaks; ignore the resulting error.
        while stdin.write_all(&block).is_ok() {}
    });

    // Wait until encryption is genuinely underway: the pre-fix build grows
    // `interrupted.enc`, the post-fix build grows a `.tmp.` sibling.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let output_started = fs::metadata(&encrypted_path).map(|m| m.len() > 0).unwrap_or(false);
        let temp_started = temp_artifacts(&dir).iter().any(|name| {
            fs::metadata(dir.join(name)).map(|m| m.len() > 0).unwrap_or(false)
        });
        if output_started || temp_started {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(150));

    child.kill().unwrap();
    child.wait().unwrap();
    let _ = writer.join();

    // Core assertion: no partial ciphertext at the destination. A SIGKILL cannot
    // run Drop, so the 0-byte placeholder legitimately survives — but it must
    // never contain data that could be mistaken for a completed backup.
    if let Ok(meta) = fs::metadata(&encrypted_path) {
        assert_eq!(meta.len(), 0,
                   "Interrupted encryption left {} bytes of partial output at the destination",
                   meta.len());
        assert_ne!(fs::read(&encrypted_path).unwrap().get(..4), Some(&b"PQE1"[..]),
                   "Interrupted encryption left a pqenc header at the destination");
    }

    // Guard against the test passing vacuously: confirm real ciphertext was in
    // flight at kill time, and that it was accumulating at the temp path.
    let leftovers = temp_artifacts(&dir);
    assert!(!leftovers.is_empty(),
            "Expected an orphaned temp file after SIGKILL; encryption may not have started");
    let temp_bytes = fs::read(dir.join(&leftovers[0])).unwrap();
    assert_eq!(temp_bytes.get(..4), Some(&b"PQE1"[..]),
               "Temp file should hold the real output stream");
}
