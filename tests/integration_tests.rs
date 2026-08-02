mod helpers;
use helpers::{TempTestEnv, TestData, TEST_PASSPHRASE};
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

/// Must match `RESERVATION_MARKER` in src/main.rs. Duplicated, not shared:
/// integration tests only exercise the compiled binary via subprocess and
/// have no access to private items.
const EXPECTED_RESERVATION_MARKER: &[u8] = b"PQENC-RESERVED-PLACEHOLDER\n";

/// Must match `RESERVATION_STALE_AGE` in src/main.rs. Duplicated for the
/// same reason as `EXPECTED_RESERVATION_MARKER` above.
const RECLAIM_STALE_AGE: std::time::Duration = std::time::Duration::from_secs(300);

#[test]
fn test_full_workflow_small_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_data = TestData::text("Hello, post-quantum world!");
    let input_path = env.create_file("input.txt", &input_data.plaintext);
    let encrypted_path = env.file_path("encrypted.enc");
    let decrypted_path = env.file_path("decrypted.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Decrypt
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, input_data.plaintext);
}

#[test]
fn test_sha256_matches_before_encryption_and_after_decryption() {
    use sha2::{Digest, Sha256};

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_data = TestData::random(50_000);
    let input_path = env.create_file("payload.bin", &input_data.plaintext);
    let encrypted_path = env.file_path("payload.bin.pqe");
    let decrypted_path = env.file_path("payload_restored.bin");

    let original_hash = Sha256::digest(&input_data.plaintext);

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

    let decrypted_hash = Sha256::digest(fs::read(&decrypted_path).unwrap());

    assert_eq!(
        original_hash, decrypted_hash,
        "SHA256 of the decrypted output must match SHA256 of the original input"
    );
}

#[test]
fn test_empty_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("empty.txt", b"");
    let encrypted_path = env.file_path("empty.enc");
    let decrypted_path = env.file_path("empty_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Decrypt
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, b"");
}

#[test]
fn test_exactly_one_chunk() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let data = vec![0x42; 64 * 1024];
    let input_path = env.create_file("onechunk.bin", &data);
    let encrypted_path = env.file_path("onechunk.enc");
    let decrypted_path = env.file_path("onechunk_dec.bin");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Decrypt
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_wrong_passphrase_fails() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let data = b"secret data";
    let input_path = env.create_file("secret.txt", data);
    let encrypted_path = env.file_path("secret.enc");
    let decrypted_path = env.file_path("secret_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Try to decrypt with wrong passphrase
    let result = env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        "wrong-passphrase",
    );

    assert!(result.is_err());
}

#[test]
fn test_generate_keys_empty_passphrase_stores_unencrypted() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase("");

    let pem_text = fs::read(&priv_key).unwrap();
    let pem_text = String::from_utf8_lossy(&pem_text);
    assert!(
        pem_text.contains("-----BEGIN PQENC PRIVATE KEY-----"),
        "Private key should use the plain-text PEM header, got: {}",
        pem_text
    );
    assert!(
        !pem_text.contains("ENCRYPTED"),
        "Private key should not be marked encrypted, got: {}",
        pem_text
    );

    let data = b"secret data";
    let input_path = env.create_file("secret.txt", data);
    let encrypted_path = env.file_path("secret.enc");
    let decrypted_path = env.file_path("secret_dec.txt");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    // No --passphrase and stdin closed: decrypt must not reach a passphrase
    // prompt at all for a plain-text key, or this would hang/fail on a
    // closed-stdin read instead of succeeding.
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            "--decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Decrypt of plain-text key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&decrypted_path).unwrap(), data);
}

#[test]
fn test_decrypt_unencrypted_key_ignores_supplied_passphrase() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase("");

    let data = b"secret data";
    let input_path = env.create_file("secret.txt", data);
    let encrypted_path = env.file_path("secret.enc");
    let decrypted_path = env.file_path("secret_dec.txt");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    // A script that always passes a passphrase variable shouldn't need to
    // special-case a plain-text key: the passphrase should just be ignored.
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            "--decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            "some-unrelated-value",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Decrypt of plain-text key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&decrypted_path).unwrap(), data);
}

#[test]
fn test_file_format_has_magic_bytes() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("test.txt", b"test");
    let encrypted_path = env.file_path("test.enc");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let encrypted = fs::read(&encrypted_path).unwrap();
    assert_eq!(&encrypted[..4], b"PQE2");
}

#[test]
fn test_optional_output_defaults_round_trip() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("notes.txt", b"optional output round trip");

    // Encrypt without -o: should default to <input>.pqe
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected_encrypted_path = env.file_path("notes.txt.pqe");
    assert!(
        expected_encrypted_path.exists(),
        "expected {:?} to exist",
        expected_encrypted_path
    );

    // Remove the plaintext so decrypt has to genuinely restore it, rather
    // than a coincidental leftover masking a bug.
    fs::remove_file(&input_path).unwrap();

    // Decrypt without -o: should restore the original filename, captured
    // via Path::file_name() at encrypt time, next to the .pqe file.
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            "--decrypt",
            expected_encrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        input_path.exists(),
        "expected restored file at {:?}",
        input_path
    );
    assert_eq!(
        fs::read(&input_path).unwrap(),
        b"optional output round trip"
    );
}

#[cfg(unix)]
#[test]
fn test_decrypt_restores_original_mtime() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("timed.bin", b"timestamp restoration test");

    // A deliberately distinctive mtime, far from "now" and from the file's
    // creation time, so a coincidental match can't hide a bug.
    let distinctive = filetime::FileTime::from_unix_time(1_600_000_000, 0);
    filetime::set_file_mtime(&input_path, distinctive).unwrap();

    let encrypted_path = env.file_path("timed.bin.pqe");
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decrypted_path = env.file_path("timed_restored.bin");
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            "--decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let restored_meta = fs::metadata(&decrypted_path).unwrap();
    let restored_mtime = filetime::FileTime::from_last_modification_time(&restored_meta);
    assert_eq!(
        restored_mtime.unix_seconds(),
        distinctive.unix_seconds(),
        "decrypted file's mtime should match the original input's mtime"
    );
}

#[test]
fn test_large_file_multiple_chunks() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let data = TestData::random(10 * 1024 * 1024); // 10MB - multiple chunks
    let input_path = env.create_file("large.bin", &data.plaintext);
    let encrypted_path = env.file_path("large.enc");
    let decrypted_path = env.file_path("large_dec.bin");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Decrypt
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

    let decrypted = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, data.plaintext);
}

#[test]
fn test_exact_multiple_of_chunk_size_with_trailer() {
    // Dedicated, non-random regression test (as opposed to
    // property_tests.rs's randomized chunk-count tests) for the checksum
    // trailer's trickiest interaction with chunking: when the input size is
    // an exact multiple of CHUNK_SIZE, the true last chunk's ciphertext is
    // exactly CHUNK_SIZE+TAG_SIZE bytes, so decrypt's read of that chunk
    // must stop precisely at the trailer boundary without either
    // over-reading into the trailer or misclassifying the last chunk as
    // AAD_CHUNK_TYPE_NORMAL because the trailer shifted the raw file length.
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let chunk_size = 64 * 1024;
    let data = TestData::random(2 * chunk_size);
    let input_path = env.create_file("twochunk.bin", &data.plaintext);
    let encrypted_path = env.file_path("twochunk.enc");
    let decrypted_path = env.file_path("twochunk_dec.bin");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();

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
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("input.txt", b"data to encrypt");

    // Occupy the output path with content we can recognize afterwards.
    const SENTINEL: &[u8] = b"pre-existing file that must not be touched";
    let encrypted_path = env.create_file("occupied.enc", SENTINEL);

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "Encryption must refuse to overwrite an existing output file"
    );

    // create_new never truncates, so the original bytes must survive intact.
    assert_eq!(
        fs::read(&encrypted_path).unwrap(),
        SENTINEL,
        "Pre-existing output file was modified"
    );

    // The rejection must happen before any temp file is created.
    let leftovers = temp_artifacts(encrypted_path.parent().unwrap());
    assert!(
        leftovers.is_empty(),
        "Rejected run left temp artifacts behind: {:?}",
        leftovers
    );
}

#[test]
fn test_encrypt_success_leaves_no_temp_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let data = TestData::random(256 * 1024); // spans multiple 64KB chunks
    let input_path = env.create_file("input.bin", &data.plaintext);
    let encrypted_path = env.file_path("clean.enc");
    let decrypted_path = env.file_path("clean_dec.bin");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A missing disarm() or a rename mistake would strand the temp file here,
    // silently accumulating one stale copy per backup run.
    let leftovers = temp_artifacts(encrypted_path.parent().unwrap());
    assert!(
        leftovers.is_empty(),
        "Successful run left temp artifacts behind: {:?}",
        leftovers
    );

    // The renamed file must still be the real, decryptable output.
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(fs::read(&decrypted_path).unwrap(), data.plaintext);
}

#[cfg(unix)]
#[test]
fn test_encrypted_output_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("input.txt", b"permission check");
    let encrypted_path = env.file_path("perms.enc");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // fs::rename carries the temp file's mode to the destination, so this is
    // really asserting that the temp file was created with ENCRYPT_OUTPUT_MODE.
    // 0o600 is umask-independent, which is what makes this deterministic.
    let mode = fs::metadata(&encrypted_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Encrypted output should be owner-only, got {:o}",
        mode
    );
}

/// Regression test for partial output on interrupted encryption, and for
/// TODO.md #1's fix: a SIGKILL'd run must leave a reclaimable placeholder,
/// not a permanent blocker.
///
/// Kills pqenc mid-stream and asserts nothing resembling a finished backup was
/// left at the output path. Against the pre-atomicity implementation, which
/// streamed the header and chunks straight to `output_path`, this fails.
/// Then retries a real encrypt to the same output path and asserts it
/// succeeds — against the pre-reclaim implementation, which left an empty,
/// permanently blocking stump at that path, this fails.
///
/// stdin is deliberately never closed, so the child cannot reach EOF and finish
/// on its own no matter how fast it encrypts — that is what keeps the timing
/// non-flaky. The writer thread stops when the kill breaks the pipe.
#[cfg(unix)]
#[test]
fn test_encrypt_killed_midstream_leaves_reclaimable_placeholder() {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("interrupted.enc");
    let dir = encrypted_path.parent().unwrap().to_path_buf();

    let mut child = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            "-",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
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
        let output_started = fs::metadata(&encrypted_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        let temp_started = temp_artifacts(&dir).iter().any(|name| {
            fs::metadata(dir.join(name))
                .map(|m| m.len() > 0)
                .unwrap_or(false)
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

    // Core assertion: no partial ciphertext at the destination. A SIGKILL
    // cannot run Drop, so the placeholder legitimately survives — but it
    // must hold exactly pqenc's own recognizable reservation marker, never
    // data that could be mistaken for a completed backup.
    if let Ok(contents) = fs::read(&encrypted_path) {
        assert_eq!(
            contents, EXPECTED_RESERVATION_MARKER,
            "Interrupted encryption should leave pqenc's reservation placeholder verbatim, not partial output"
        );
    }

    // Guard against the test passing vacuously: confirm real ciphertext was in
    // flight at kill time, and that it was accumulating at the temp path.
    let leftovers = temp_artifacts(&dir);
    assert!(
        !leftovers.is_empty(),
        "Expected an orphaned temp file after SIGKILL; encryption may not have started"
    );
    let temp_bytes = fs::read(dir.join(&leftovers[0])).unwrap();
    assert_eq!(
        temp_bytes.get(..4),
        Some(&b"PQE2"[..]),
        "Temp file should hold the real output stream"
    );

    // Follow-up: retry is no longer permanently blocked. Reclaim requires
    // the placeholder to be RECLAIM_STALE_AGE old (so a live concurrent run
    // is never mistaken for a dead one) -- this process's own placeholder
    // is only milliseconds old, so backdate its mtime to simulate a retry
    // long after the crash, the way the real motivating scenario actually
    // plays out, without the test itself sleeping for minutes.
    filetime::set_file_mtime(
        &encrypted_path,
        filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - RECLAIM_STALE_AGE - Duration::from_secs(1),
        ),
    )
    .unwrap();

    // A second, real (non-killed) encrypt to the exact same output path must
    // now succeed -- the leftover placeholder must be recognized as pqenc's
    // own and reclaimed.
    let retry_input = env.create_file("retry_input.txt", b"retry after SIGKILL must succeed");
    let retry_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            retry_input.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        retry_output.status.success(),
        "Retry to the same output path after a SIGKILL should succeed, not be blocked by the leftover placeholder: {}",
        String::from_utf8_lossy(&retry_output.stderr)
    );

    // And it must be real, valid ciphertext -- round-trip it.
    let retry_decrypted = env.file_path("retry_decrypted.txt");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        retry_decrypted.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(
        fs::read(&retry_decrypted).unwrap(),
        b"retry after SIGKILL must succeed"
    );

    // The retry's own temp file is renamed away and disarmed on success, same
    // as any normal encrypt -- it must not add a NEW leftover. The original
    // kill's own orphaned temp file (`leftovers`, asserted non-empty above)
    // is a separate, pre-existing artifact this fix was never meant to clean
    // up -- only the output-path placeholder is reclaimed -- so it's expected
    // to still be there; assert the count didn't grow, not that it's zero.
    assert_eq!(
        temp_artifacts(&dir).len(),
        leftovers.len(),
        "Successful retry should not leave a new temp artifact behind"
    );
}

/// Run `generate-keys` with stdin closed. Only for checks that must fail
/// *before* the passphrase prompt — reaching the prompt with no stdin produces an
/// unrelated read error, which would make a test pass for the wrong reason.
fn run_generate_keys(
    pub_path: &std::path::Path,
    priv_path: &std::path::Path,
) -> std::process::Output {
    Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_path.to_str().unwrap(),
            "--private-key",
            priv_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

/// Run `generate-keys` supplying the passphrase directly, so execution
/// reaches the file writes. Required by any test about write behavior.
#[cfg(unix)]
fn run_generate_keys_answering_prompts(
    pub_path: &std::path::Path,
    priv_path: &std::path::Path,
) -> std::process::Output {
    Command::new(pqenc_binary())
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
        .unwrap()
}

#[test]
fn test_generate_keys_rejects_occupied_path_before_prompting() {
    const SENTINEL: &[u8] = b"an existing key file that must not be touched";

    // Occupied public key path.
    let env = TempTestEnv::new();
    let occupied = env.create_file("existing_pub.key", SENTINEL);
    let fresh = env.file_path("fresh_priv.key");

    let output = run_generate_keys(&occupied, &fresh);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !output.status.success(),
        "Keygen must refuse an occupied path"
    );
    assert!(
        stderr.contains("already exists"),
        "Error should name the conflict, got: {}",
        stderr
    );
    // The whole point of the advisory pre-check: fail before spending ~1-2s on
    // key generation and making the user type a passphrase twice.
    assert!(
        !stderr.contains("Enter passphrase for"),
        "Keygen prompted for a passphrase before detecting the conflict: {}",
        stderr
    );
    assert_eq!(
        fs::read(&occupied).unwrap(),
        SENTINEL,
        "Existing file was modified"
    );
    assert!(
        !fresh.exists(),
        "Nothing should have been written to the other path"
    );

    // Occupied private key path.
    let env = TempTestEnv::new();
    let fresh = env.file_path("fresh_pub.key");
    let occupied = env.create_file("existing_priv.key", SENTINEL);

    let output = run_generate_keys(&fresh, &occupied);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !output.status.success(),
        "Keygen must refuse an occupied path"
    );
    assert!(
        !stderr.contains("Enter passphrase for"),
        "Keygen prompted before detecting the conflict: {}",
        stderr
    );
    assert_eq!(
        fs::read(&occupied).unwrap(),
        SENTINEL,
        "Existing file was modified"
    );
    assert!(
        !fresh.exists(),
        "Nothing should have been written to the other path"
    );
}

#[test]
fn test_generate_keys_rejects_identical_paths() {
    let env = TempTestEnv::new();
    let same = env.file_path("same.key");

    let output = run_generate_keys(&same, &same);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !output.status.success(),
        "Keygen must refuse to write both keys to one path"
    );
    // Assert the specific diagnosis, not merely that something failed: with no
    // stdin, reaching the passphrase prompt also fails, which would let this pass
    // for an unrelated reason.
    assert!(
        stderr.contains("must differ"),
        "Error should name the identical-path conflict, got: {}",
        stderr
    );
    assert!(!same.exists(), "No file should have been created");
}

/// Regression test for the stranded-public-key trap.
///
/// The public key used to be written first, so a failure on the private key
/// left a public key whose private half never existed — everything encrypted to
/// it would be unrecoverable. Triggering that needs a failure the advisory
/// pre-check cannot see, so the private key targets a read-only directory.
#[cfg(unix)]
#[test]
fn test_generate_keys_leaves_no_public_key_when_private_write_fails() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let locked_dir = env.file_path("locked");
    fs::create_dir(&locked_dir).unwrap();
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o500)).unwrap();

    // root ignores the write bit, so the failure we depend on would not happen.
    if fs::write(locked_dir.join(".probe"), b"x").is_ok() {
        fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipping: running with privileges that bypass directory permissions");
        return;
    }

    let pub_path = env.file_path("stranded_pub.key");
    let priv_path = locked_dir.join("priv.key");

    // Must answer the prompts: the failure under test happens at the file
    // writes, which are only reached after the passphrase is accepted.
    let output = run_generate_keys_answering_prompts(&pub_path, &priv_path);

    // Restore before asserting so a failure cannot leave an undeletable TempDir.
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(!output.status.success(), "Keygen should have failed");
    assert!(!priv_path.exists(), "Private key should not exist");
    assert!(
        !pub_path.exists(),
        "Public key was left behind after the private key write failed - \
             it would encrypt to a private key that never existed"
    );
}

#[cfg(unix)]
#[test]
fn test_generate_keys_key_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let pub_path = env.file_path("perm_pub.key");
    let priv_path = env.file_path("perm_priv.key");

    // Set the umask in a child shell rather than the test process: umask(2) is
    // get-and-set, so reading it from a threaded test harness is racy. Args
    // after the inline script are passed through as "$0" "$@" rather than
    // interpolated into the shell string, so paths/passphrase can't be
    // misparsed by the shell.
    let output = Command::new("sh")
        .arg("-c")
        .arg(r#"umask 022; exec "$0" "$@""#)
        .arg(pqenc_binary())
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
        .unwrap();
    assert!(
        output.status.success(),
        "Key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let priv_mode = fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        priv_mode, 0o600,
        "Private key should be owner-only, got {:o}",
        priv_mode
    );

    // Deliberately not 0600: the public key is meant to be distributed.
    let pub_mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        pub_mode, 0o644,
        "Public key should follow umask, got {:o}",
        pub_mode
    );
}

#[test]
fn test_generate_keys_leaves_no_temp_artifacts() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Keys are written in place rather than staged through temp files. Key
    // files share a directory with encrypted output in these tests, so a future
    // staging refactor that stranded a `.tmp.` file would surface as a
    // misleading failure in the encryption tests above.
    let leftovers = temp_artifacts(pub_key.parent().unwrap());
    assert!(
        leftovers.is_empty(),
        "Key generation left temp artifacts behind: {:?}",
        leftovers
    );
}

/// Extracts the "SHA256:<base64>" token from fingerprint/keygen/encrypt
/// stdout, so tests can compare fingerprints without matching the rest of
/// the surrounding text.
fn extract_sha256_fingerprint(output: &str) -> &str {
    let start = output
        .find("SHA256:")
        .expect("output should contain a SHA256: fingerprint");
    output[start..].split_whitespace().next().unwrap()
}

#[test]
fn test_generate_keys_prints_fingerprint_and_randomart() {
    let env = TempTestEnv::new();
    let pub_key = env.file_path("pub.key");
    let priv_key = env.file_path("priv.key");

    let output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Key fingerprint is:\nSHA256:"),
        "stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("Key's randomart image is:"),
        "stdout: {}",
        stdout
    );
    assert!(stdout.contains("+--[ML-KEM-1024]--+"), "stdout: {}", stdout);
    assert!(stdout.contains("+----[SHA256]-----+"), "stdout: {}", stdout);
}

#[test]
fn test_fingerprint_command_matches_for_public_and_private_key() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let from_pub = Command::new(pqenc_binary())
        .args(["fingerprint", "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(from_pub.status.success());
    let from_pub_stdout = String::from_utf8_lossy(&from_pub.stdout).into_owned();

    let from_priv = Command::new(pqenc_binary())
        .args([
            "fingerprint",
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .unwrap();
    assert!(from_priv.status.success());
    let from_priv_stdout = String::from_utf8_lossy(&from_priv.stdout).into_owned();

    assert_eq!(
        extract_sha256_fingerprint(&from_pub_stdout),
        extract_sha256_fingerprint(&from_priv_stdout),
        "fingerprint from public and private key files must match for the same keypair"
    );

    assert!(from_pub_stdout.contains("The key's randomart image is:"));
    assert!(from_priv_stdout.contains("The key's randomart image is:"));
}

#[test]
fn test_fingerprint_requires_exactly_one_key_source() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Neither flag supplied.
    let neither = Command::new(pqenc_binary())
        .args(["fingerprint"])
        .output()
        .unwrap();
    assert!(!neither.status.success());

    // Both flags supplied.
    let both = Command::new(pqenc_binary())
        .args([
            "fingerprint",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!both.status.success());
}

#[test]
fn test_encrypt_prints_recipient_fingerprint_matching_key_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("input.txt", b"hello");
    let encrypted_path = env.file_path("input.enc");

    let encrypt_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "--encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(encrypt_output.status.success());
    let encrypt_stdout = String::from_utf8_lossy(&encrypt_output.stdout).into_owned();

    assert!(
        encrypt_stdout.contains("Recipient key fingerprint is:"),
        "stdout: {}",
        encrypt_stdout
    );
    assert!(
        encrypt_stdout.contains("Recipient key's randomart image is:"),
        "stdout: {}",
        encrypt_stdout
    );

    let fingerprint_output = Command::new(pqenc_binary())
        .args(["fingerprint", "--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    let fingerprint_stdout = String::from_utf8_lossy(&fingerprint_output.stdout).into_owned();

    assert_eq!(
        extract_sha256_fingerprint(&encrypt_stdout),
        extract_sha256_fingerprint(&fingerprint_stdout),
        "encrypt should report the same fingerprint as the fingerprint command"
    );
}
