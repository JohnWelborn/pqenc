mod helpers;
use helpers::{TempTestEnv, TestData, TEST_PASSPHRASE};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

fn tar_available() -> bool {
    Command::new("tar")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Names of leftover atomic-write temp files (`<output>.tmp.<hex>`) in `dir`.
fn temp_artifacts(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect()
}

/// Recursively searches `dir` for a file named `name` and returns its
/// content. Used to check roundtrip content without assuming what basename
/// the archiver picked for the directory's top-level tar entry.
fn find_file_content(dir: &Path, name: &str) -> Option<Vec<u8>> {
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_content(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|f| f == name) {
            return Some(fs::read(&path).unwrap());
        }
    }
    None
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_via_tar_command() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let dir_name = "data";
    let dir_path = env.file_path(dir_name);
    fs::create_dir_all(&dir_path).unwrap();

    let test_content = b"hello world";
    let test_file = "file.txt";
    fs::write(dir_path.join(test_file), test_content).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let encrypted_path = env.file_path("archive.tar.gz.pqe");
    let pqenc_bin = pqenc_binary();

    // Encrypt: tar czf - data | pqenc encrypt
    let mut tar = Command::new("tar")
        .args(["czf", "-", dir_name])
        .current_dir(env.file_path("."))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn tar");
    let tar_stdout = tar.stdout.take().expect("Failed to capture tar stdout");

    let mut enc = Command::new(&pqenc_bin)
        .args([
            "encrypt",
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
    assert_eq!(&magic, b"PQE4");
    drop(file);

    // Decrypt: pqenc decrypt | tar xzf -
    let extract_dir = env.file_path("extracted");
    fs::create_dir(&extract_dir).unwrap();

    let decrypted_tar_path = env.file_path("decrypted.tar.gz");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_tar_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

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
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let dir_name = "data";
    let dir_path = env.file_path(dir_name);
    fs::create_dir_all(&dir_path).unwrap();

    let test_content = b"stdin shorthand test";
    let test_file = "file.txt";
    fs::write(dir_path.join(test_file), test_content).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let encrypted_path = env.file_path("archive.tar.gz.pqe");
    let pqenc_bin = pqenc_binary();

    // Encrypt using "-" as stdin shorthand instead of "/dev/stdin"
    let mut tar = Command::new("tar")
        .args(["czf", "-", dir_name])
        .current_dir(env.file_path("."))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn tar");
    let tar_stdout = tar.stdout.take().expect("Failed to capture tar stdout");

    let mut enc = Command::new(&pqenc_bin)
        .args([
            "encrypt",
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
    let decrypted_tar_path = env.file_path("decrypted.tar.gz");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_tar_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted");
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

#[test]
#[cfg(unix)]
fn test_encrypt_directory_native_default_output_roundtrip() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let dir_path = env.file_path("mydir");
    fs::create_dir_all(&dir_path).unwrap();
    let test_content = b"native directory encryption";
    fs::write(dir_path.join("file.txt"), test_content).unwrap();

    let (public_key_path, private_key_path) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Encrypt with no --output: should default to <dir>.tar.gz.pqe.
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            dir_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt failed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    let expected_encrypted_path = env.file_path("mydir.tar.gz.pqe");
    assert!(
        expected_encrypted_path.exists(),
        "expected default output at {:?}",
        expected_encrypted_path
    );

    // Decrypt with no --output: should default to <dir>.tar.gz, driven by
    // the embedded metadata filename, not the ciphertext's own filename.
    let dec_output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            expected_encrypted_path.to_str().unwrap(),
            "--private-key",
            private_key_path.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .expect("Failed to run pqenc decrypt");
    assert!(
        dec_output.status.success(),
        "pqenc decrypt failed: {}",
        String::from_utf8_lossy(&dec_output.stderr)
    );

    let expected_decrypted_path = env.file_path("mydir.tar.gz");
    assert!(
        expected_decrypted_path.exists(),
        "expected default decrypted output at {:?}",
        expected_decrypted_path
    );

    let extract_dir = env.file_path("extracted");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", expected_decrypted_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    let extracted_content = fs::read(extract_dir.join("mydir").join("file.txt")).unwrap();
    assert_eq!(extracted_content, test_content);
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_native_explicit_output_keeps_embedded_name() {
    let env = TempTestEnv::new();
    let dir_path = env.file_path("mydir");
    fs::create_dir_all(&dir_path).unwrap();
    fs::write(dir_path.join("file.txt"), b"content").unwrap();

    let (public_key_path, private_key_path) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let custom_encrypted_path = env.file_path("custom_name.pqe");
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            dir_path.to_str().unwrap(),
            "--output",
            custom_encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt failed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    // Decrypt with no --output: the produced filename must come from the
    // embedded metadata ("mydir.tar.gz"), independent of the ciphertext's
    // own filename ("custom_name.pqe").
    let dec_output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            custom_encrypted_path.to_str().unwrap(),
            "--private-key",
            private_key_path.to_str().unwrap(),
            "--passphrase",
            TEST_PASSPHRASE,
        ])
        .output()
        .expect("Failed to run pqenc decrypt");
    assert!(
        dec_output.status.success(),
        "pqenc decrypt failed: {}",
        String::from_utf8_lossy(&dec_output.stderr)
    );

    assert!(
        env.file_path("mydir.tar.gz").exists(),
        "decrypt should have used the embedded name, not one derived from custom_name.pqe"
    );
    assert!(!env.file_path("custom_name.tar.gz").exists());
    assert!(!env.file_path("custom_name").exists());
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_native_preserves_symlink() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let dir_path = env.file_path("mydir");
    fs::create_dir_all(&dir_path).unwrap();
    fs::write(dir_path.join("target.txt"), b"link target content").unwrap();
    std::os::unix::fs::symlink("target.txt", dir_path.join("link")).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("mydir.tar.gz.pqe");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            dir_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt failed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("mydir.tar.gz").to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", env.file_path("mydir.tar.gz").to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    let extracted_link = extract_dir.join("mydir").join("link");
    let link_meta = fs::symlink_metadata(&extracted_link)
        .expect("extracted link should exist as its own directory entry");
    assert!(
        link_meta.file_type().is_symlink(),
        "symlink inside the encrypted directory must survive as a symlink, not be dereferenced"
    );
    assert_eq!(
        fs::read_link(&extracted_link).unwrap(),
        Path::new("target.txt")
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_native_multi_file_multi_chunk() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let dir_path = env.file_path("mydir");
    fs::create_dir_all(&dir_path).unwrap();

    // Several files comfortably exceeding both CHUNK_SIZE (64 KiB) and a
    // typical OS pipe buffer, so the archiving thread genuinely blocks on
    // backpressure at least once. This only exercises multiple *chunks*,
    // not multiple *segments* -- chunks_per_segment is fixed to the real
    // 8 GiB CHUNKS_PER_SEGMENT via the CLI binary; the smaller-segment test
    // seam is only reachable from in-crate src/tests.rs unit tests.
    let files: Vec<(String, TestData)> = (0..4)
        .map(|i| (format!("file{i}.bin"), TestData::random(700_000)))
        .collect();
    for (name, data) in &files {
        fs::write(dir_path.join(name), &data.plaintext).unwrap();
    }

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("mydir.tar.gz.pqe");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            dir_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt failed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        env.file_path("mydir.tar.gz").to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", env.file_path("mydir.tar.gz").to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    for (name, data) in &files {
        let extracted = fs::read(extract_dir.join("mydir").join(name)).unwrap();
        assert_eq!(extracted, data.plaintext, "content mismatch for {name}");
    }
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_native_archiving_failure_leaves_no_output() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let dir_path = env.file_path("mydir");
    fs::create_dir_all(&dir_path).unwrap();
    fs::write(dir_path.join("ok.txt"), b"readable").unwrap();
    let unreadable_path = dir_path.join("unreadable.txt");
    fs::write(&unreadable_path, b"secret").unwrap();
    fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();

    // root ignores the read bit, so the archiving failure this test depends
    // on would not happen.
    if fs::read(&unreadable_path).is_ok() {
        fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();
        eprintln!("skipping: running with privileges that bypass file permissions");
        return;
    }

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("mydir.tar.gz.pqe");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            dir_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");

    // Restore permissions before any assertion, so a failing assertion can
    // never strand an unreadable file inside a TempDir that then can't
    // clean itself up on drop.
    fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(
        !enc_output.status.success(),
        "encrypt should fail when a file inside the directory can't be read"
    );
    assert!(
        !encrypted_path.exists(),
        "no output file should be left behind after a failed archive"
    );
    assert!(
        temp_artifacts(&env.file_path(".")).is_empty(),
        "no leftover .tmp. sibling should be left behind after a failed archive"
    );
}

// Regression tests for: `pqenc encrypt .` / `pqenc encrypt ..` always fail,
// even with an explicit `--output`, because directory encryption
// unconditionally derives a basename from the input path (to name the tar's
// internal top-level entry / embedded metadata filename) and bails when
// `Path::file_name()` can't produce one -- which is true for ".", "..", "/",
// and any path ending in "..", regardless of whether `--output` already
// supplies everything needed to know where to write the ciphertext.

#[test]
#[cfg(unix)]
fn test_encrypt_directory_dot_with_explicit_output_succeeds() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let work_dir = env.file_path("work");
    fs::create_dir_all(&work_dir).unwrap();
    let test_content = b"backing up the current directory";
    fs::write(work_dir.join("file.txt"), test_content).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("dot.pqe");

    // cd into `work_dir` and encrypt "." -- the common "back up the current
    // directory" case from the bug report.
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            ".",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .current_dir(&work_dir)
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt . --output should succeed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    let decrypted_path = env.file_path("dot.tar.gz");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted_dot");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", decrypted_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    assert_eq!(
        find_file_content(&extract_dir, "file.txt").as_deref(),
        Some(test_content.as_slice()),
        "decrypted archive should contain the original file's content"
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_dotdot_with_explicit_output_succeeds() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    let env = TempTestEnv::new();
    let parent_dir = env.file_path("parent");
    let child_dir = parent_dir.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    let test_content = b"backing up the parent directory";
    fs::write(parent_dir.join("marker.txt"), test_content).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("dotdot.pqe");

    // cd into `child_dir` and encrypt ".." -- resolves to `parent_dir`.
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "..",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .current_dir(&child_dir)
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt .. --output should succeed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    let decrypted_path = env.file_path("dotdot.tar.gz");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted_dotdot");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", decrypted_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    assert_eq!(
        find_file_content(&extract_dir, "marker.txt").as_deref(),
        Some(test_content.as_slice()),
        "decrypted archive should contain the parent directory's content"
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_path_ending_in_dotdot_with_explicit_output_succeeds() {
    if !tar_available() {
        eprintln!("Skipping test: tar not available");
        return;
    }

    // Same underlying bug as the literal ".." case, but reached through a
    // longer path that merely *ends* in "..", with no cwd change involved --
    // `Path::file_name()` returns `None` for this shape too.
    let env = TempTestEnv::new();
    let parent_dir = env.file_path("parent2");
    let child_dir = parent_dir.join("child");
    fs::create_dir_all(&child_dir).unwrap();
    let test_content = b"trailing dotdot path";
    fs::write(parent_dir.join("marker.txt"), test_content).unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("trailing_dotdot.pqe");
    let input_arg = child_dir.join("..");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_arg.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");
    assert!(
        enc_output.status.success(),
        "pqenc encrypt <path ending in ..> --output should succeed: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    let decrypted_path = env.file_path("trailing_dotdot.tar.gz");
    env.decrypt_file_with_passphrase(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        TEST_PASSPHRASE,
    )
    .expect("pqenc decrypt failed");

    let extract_dir = env.file_path("extracted_trailing_dotdot");
    fs::create_dir(&extract_dir).unwrap();
    let untar_status = Command::new("tar")
        .args(["xzf", decrypted_path.to_str().unwrap()])
        .current_dir(&extract_dir)
        .status()
        .expect("Failed to run tar extract");
    assert!(untar_status.success(), "tar extract failed");

    assert_eq!(
        find_file_content(&extract_dir, "marker.txt").as_deref(),
        Some(test_content.as_slice()),
        "decrypted archive should contain the original directory's content"
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_dot_error_message_is_not_misleading_about_output() {
    // Today this fails even with --output, yet the error text says to pass
    // one -- pin down that once the underlying bug is fixed, encrypt . with
    // an explicit --output no longer produces this specific misleading
    // message. (It may still fail for some *other* reason in principle, but
    // must not fail with "pass an explicit --output" while --output is
    // already present.)
    let env = TempTestEnv::new();
    let work_dir = env.file_path("work_msg");
    fs::create_dir_all(&work_dir).unwrap();
    fs::write(work_dir.join("file.txt"), b"content").unwrap();

    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("dot_msg.pqe");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            ".",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .current_dir(&work_dir)
        .output()
        .expect("Failed to run pqenc encrypt");

    let stderr = String::from_utf8_lossy(&enc_output.stderr);
    assert!(
        !stderr.contains("pass an explicit --output"),
        "encrypt . --output <path> should not fail by telling the user to pass --output \
         when they already did; got: {stderr}"
    );
}

#[test]
#[cfg(unix)]
fn test_encrypt_directory_root_slash_fails_with_accurate_message() {
    // Unlike "." / ".." / trailing-".." paths, "/" has no basename at any
    // resolution depth, so directory encryption still rejects it -- but the
    // message must no longer suggest --output as a fix, since --output was
    // never the problem. This is safe to run for real: the rejection happens
    // at the naming step (before the archiving pipe/thread is spawned), so
    // it never attempts to walk the filesystem.
    let env = TempTestEnv::new();
    let (public_key_path, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let encrypted_path = env.file_path("root.pqe");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "/",
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            public_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run pqenc encrypt");

    assert!(
        !enc_output.status.success(),
        "encrypt / should still fail (the filesystem root has no basename)"
    );
    let stderr = String::from_utf8_lossy(&enc_output.stderr);
    assert!(
        stderr.contains("filesystem root"),
        "expected an accurate 'filesystem root' message; got: {stderr}"
    );
    assert!(
        !stderr.contains("pass an explicit --output"),
        "encrypt / should not blame --output for a failure --output can't fix; got: {stderr}"
    );
    assert!(
        !encrypted_path.exists(),
        "no output file should be left behind after a rejected directory name"
    );
}
