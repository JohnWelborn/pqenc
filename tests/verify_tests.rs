mod helpers;
use helpers::{TempTestEnv, TestData, TEST_PASSPHRASE};
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

/// Encrypts `plaintext` and returns the resulting `.pqe` file's raw bytes.
fn encrypt_bytes(env: &TempTestEnv, name: &str, plaintext: &[u8]) -> Vec<u8> {
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let input_path = env.create_file(name, plaintext);
    let encrypted_path = env.file_path(&format!("{name}.pqe"));

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

    fs::read(&encrypted_path).unwrap()
}

fn run_verify(path: &std::path::Path) -> std::process::Output {
    Command::new(pqenc_binary())
        .args(["verify", "--verify", path.to_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
fn test_verify_valid_file_passes() {
    let env = TempTestEnv::new();
    let bytes = encrypt_bytes(&env, "data.bin", b"some content to verify");
    let path = env.file_path("data.bin.pqe");
    fs::write(&path, &bytes).unwrap();

    let output = run_verify(&path);
    assert!(
        output.status.success(),
        "verify should pass for an untampered file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("VALID"),
        "expected a VALID message, got: {stdout}"
    );
}

#[test]
fn test_verify_detects_corrupted_trailer() {
    let env = TempTestEnv::new();
    let mut bytes = encrypt_bytes(&env, "data.bin", b"some content to verify");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let path = env.file_path("data.bin.pqe");
    fs::write(&path, &bytes).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should fail on a corrupted trailer"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CHECKSUM MISMATCH"),
        "expected a checksum mismatch error, got: {stderr}"
    );
}

#[test]
fn test_verify_detects_body_corruption() {
    let env = TempTestEnv::new();
    let data = TestData::random(200_000); // multi-chunk, so the flip lands well inside the body
    let mut bytes = encrypt_bytes(&env, "multi.bin", &data.plaintext);
    let pos = bytes.len() / 2;
    bytes[pos] ^= 0x01;
    let path = env.file_path("multi.bin.pqe");
    fs::write(&path, &bytes).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should fail when the ciphertext body is corrupted"
    );
}

#[test]
fn test_verify_detects_header_corruption() {
    // Distinct from AEAD-based header-tamper detection at decrypt time
    // (tests/security_tests.rs::test_header_tampering_detected): this
    // confirms the checksum path itself independently notices header
    // corruption, not just body corruption, since the trailer covers the
    // whole file including the header.
    let env = TempTestEnv::new();
    let mut bytes = encrypt_bytes(&env, "data.bin", b"some content to verify");
    // Offset 20 is well inside the KEM ciphertext field (starts at byte 8),
    // clear of the magic bytes and length prefix.
    bytes[20] ^= 0xFF;
    let path = env.file_path("data.bin.pqe");
    fs::write(&path, &bytes).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should fail when the header is corrupted"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CHECKSUM MISMATCH"),
        "expected a checksum mismatch error, got: {stderr}"
    );
}

#[test]
fn test_verify_detects_trailer_exactly_removed() {
    // Marker still says a trailer is present, but exactly TRAILER_SIZE (32)
    // bytes are missing from the end -- distinct boundary case from both
    // "corrupted trailer" (same length, wrong bytes) and "pre-trailer
    // format" (marker absent). The real last ciphertext bytes get misread
    // as the trailer and, barring astronomical coincidence, fail to match.
    let env = TempTestEnv::new();
    let bytes = encrypt_bytes(&env, "data.bin", b"some content to verify");
    let truncated = &bytes[..bytes.len() - 32];
    let path = env.file_path("data.bin.pqe");
    fs::write(&path, truncated).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should fail when the trailer is entirely missing but still declared present"
    );
}

#[test]
fn test_verify_rejects_invalid_magic() {
    let env = TempTestEnv::new();
    let mut bad_data = b"XXX1".to_vec();
    bad_data.extend_from_slice(&[0u8; 2000]);
    let path = env.file_path("bad.pqe");
    fs::write(&path, &bad_data).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should reject invalid magic bytes"
    );
}

#[test]
fn test_verify_missing_file() {
    let env = TempTestEnv::new();
    let path = env.file_path("does_not_exist.pqe");

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should fail (not panic) on a missing file"
    );
}

#[test]
fn test_verify_rejects_file_missing_checksum_trailer_marker() {
    // Simulates a file whose extension region never carried the checksum
    // trailer marker (formerly tolerated for pre-trailer PQE1/PQE2 files;
    // now that those formats are gone, the marker -- and the trailer it
    // implies -- is mandatory on every file `verify` accepts): real
    // `pqenc encrypt` output, with the extension-region trailer marker and
    // the 32-byte trailer surgically stripped back out.
    let env = TempTestEnv::new();
    let mut bytes = encrypt_bytes(&env, "data.bin", b"some content to verify");

    let kem_ct_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let ext_len_offset = 4 + 4 + kem_ct_len + 32 + 16 + 12;
    let ext_len = u32::from_be_bytes(
        bytes[ext_len_offset..ext_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    assert!(
        ext_len > 0,
        "expected a non-empty extension region carrying the trailer marker"
    );

    bytes.splice(
        ext_len_offset..ext_len_offset + 4 + ext_len,
        0u32.to_be_bytes(),
    );
    let new_len = bytes.len() - 32;
    bytes.truncate(new_len);

    let path = env.file_path("data.bin.pqe");
    fs::write(&path, &bytes).unwrap();

    let output = run_verify(&path);
    assert!(
        !output.status.success(),
        "verify should reject a file with no checksum trailer marker"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("checksum trailer"),
        "expected an error about the missing checksum trailer, got: {stderr}"
    );
}

fn run_decrypt(
    input: &std::path::Path,
    output: &std::path::Path,
    priv_key: &std::path::Path,
) -> std::process::Output {
    Command::new(pqenc_binary())
        .args([
            "decrypt",
            "--decrypt",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .unwrap()
}

#[test]
fn test_decrypt_runs_verify_first_and_prints_both_stages() {
    // decrypt now runs the same checks `pqenc verify` does as a preflight,
    // before touching the private key. On a clean file this should succeed
    // and visibly report both stages in order.
    let env = TempTestEnv::new();
    let bytes = encrypt_bytes(&env, "data.bin", b"some content to decrypt");
    let encrypted_path = env.file_path("data.bin.pqe");
    fs::write(&encrypted_path, &bytes).unwrap();
    let priv_key = env.file_path("test_priv.pem");
    let output_path = env.file_path("data_restored.bin");

    let output = run_decrypt(&encrypted_path, &output_path, &priv_key);
    assert!(
        output.status.success(),
        "decrypt should succeed on an untampered file: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let verify_pos = stdout
        .find("Running verify")
        .expect("expected a 'Running verify' message");
    let decrypt_pos = stdout
        .find("Decrypting")
        .expect("expected a 'Decrypting' message");
    assert!(
        verify_pos < decrypt_pos,
        "verify must be reported before decrypt starts: {stdout}"
    );

    assert_eq!(fs::read(&output_path).unwrap(), b"some content to decrypt");
}

#[test]
fn test_decrypt_fails_before_decrypting_when_verify_fails() {
    // A corrupted trailer must now stop decrypt at the verify preflight --
    // before the private key is even used for anything beyond loading --
    // with a checksum-mismatch error, and no output file should appear.
    let env = TempTestEnv::new();
    let mut bytes = encrypt_bytes(&env, "data.bin", b"some content to decrypt");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let encrypted_path = env.file_path("data.bin.pqe");
    fs::write(&encrypted_path, &bytes).unwrap();
    let priv_key = env.file_path("test_priv.pem");
    let output_path = env.file_path("data_restored.bin");

    let output = run_decrypt(&encrypted_path, &output_path, &priv_key);
    assert!(
        !output.status.success(),
        "decrypt should fail when the verify preflight fails"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CHECKSUM MISMATCH"),
        "expected a checksum mismatch error, got: {stderr}"
    );
    assert!(
        !output_path.exists(),
        "no output file should be created when the verify preflight fails"
    );
}

#[test]
fn test_decrypt_rejects_occupied_output_before_running_verify() {
    // An explicit --output that already exists must be reported immediately,
    // without first paying for the full-file checksum preflight -- this is
    // decrypt's fail-fast output handling. Using a corrupted input (which
    // would otherwise fail verify with CHECKSUM MISMATCH) proves the claim
    // check ran first: if verify ran before the claim, this would fail with
    // a checksum error instead, and the sentinel file would still exist but
    // that wouldn't demonstrate ordering.
    const SENTINEL: &[u8] = b"pre-existing output that must not be touched";

    let env = TempTestEnv::new();
    let mut bytes = encrypt_bytes(&env, "data.bin", b"some content to decrypt");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let encrypted_path = env.file_path("data.bin.pqe");
    fs::write(&encrypted_path, &bytes).unwrap();
    let priv_key = env.file_path("test_priv.pem");
    let output_path = env.create_file("data_restored.bin", SENTINEL);

    let output = run_decrypt(&encrypted_path, &output_path, &priv_key);
    assert!(
        !output.status.success(),
        "decrypt should refuse an occupied --output path"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected an 'already exists' error reported before the checksum scan, got: {stderr}"
    );
    assert!(
        !stderr.contains("CHECKSUM MISMATCH"),
        "verify's checksum preflight must not run before the output claim: {stderr}"
    );
    assert_eq!(
        fs::read(&output_path).unwrap(),
        SENTINEL,
        "pre-existing output file was modified"
    );
}
