mod helpers;
use helpers::{set_fake_home, write_passphrase_file, TempTestEnv, TestData, TEST_PASSPHRASE};
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

/// Must match `RESERVATION_MARKER` in src/main.rs. Duplicated, not shared:
/// integration tests only exercise the compiled binary via subprocess and
/// have no access to private items.
const EXPECTED_RESERVATION_MARKER: &[u8] = b"PQENC-RESERVED-PLACEHOLDER\n";

/// Windows DACL inspection, duplicated from `windows_security` (and its
/// `src/tests.rs` unit tests) for the same reason as
/// `EXPECTED_RESERVATION_MARKER` above: this crate only drives the compiled
/// binary as a subprocess and has no access to private items.
#[cfg(windows)]
mod windows_dacl {
    use std::collections::HashSet;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn sid_to_string(sid: PSID) -> String {
        unsafe {
            let mut string_sid: *mut u16 = std::ptr::null_mut();
            assert_ne!(ConvertSidToStringSidW(sid, &mut string_sid), 0);
            let len = (0..).take_while(|&i| *string_sid.offset(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, len));
            LocalFree(string_sid as *mut core::ffi::c_void);
            s
        }
    }

    /// The current process's user SID, in `S-1-5-...` string form.
    pub(crate) fn current_user_sid() -> String {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
                0
            );
            let mut needed: u32 = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            assert_ne!(needed, 0);
            let mut buf: Vec<u64> = vec![0u64; needed.div_ceil(8) as usize];
            assert_ne!(
                GetTokenInformation(
                    token,
                    TokenUser,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    needed,
                    &mut needed,
                ),
                0
            );
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid = sid_to_string(token_user.User.Sid);
            CloseHandle(token);
            sid
        }
    }

    /// The set of grantee SIDs in `path`'s DACL, and whether that DACL is
    /// marked protected (blocking ACEs inherited from the parent directory).
    pub(crate) fn grantees_and_protected(path: &std::path::Path) -> (HashSet<String>, bool) {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(err, 0, "GetNamedSecurityInfoW failed: {err}");

        let mut sids = HashSet::new();
        let ace_count = unsafe { (*dacl).AceCount };
        for i in 0..u32::from(ace_count) {
            let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, i, &mut ace_ptr) }, 0);
            let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
            assert_eq!(
                header.AceType, 0,
                "expected only ACCESS_ALLOWED_ACE entries"
            );
            let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
            let sid_ptr = std::ptr::addr_of!(ace.SidStart) as PSID;
            sids.insert(sid_to_string(sid_ptr));
        }

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) },
            0
        );
        let protected = control & SE_DACL_PROTECTED != 0;

        unsafe { LocalFree(sd as _) };
        (sids, protected)
    }
}

#[test]
fn test_full_workflow_small_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_data = TestData::text("Hello, post-quantum world!");
    let input_path = env.create_file("input.txt", &input_data.plaintext);
    let encrypted_path = env.file_path("encrypted.pqe");
    let decrypted_path = env.file_path("decrypted.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("empty.pqe");
    let decrypted_path = env.file_path("empty_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("onechunk.pqe");
    let decrypted_path = env.file_path("onechunk_dec.bin");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("secret.pqe");
    let decrypted_path = env.file_path("secret_dec.txt");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("secret.pqe");
    let decrypted_path = env.file_path("secret_dec.txt");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    // No --passphrase-file and stdin closed: decrypt must not reach a
    // passphrase prompt at all for a plain-text key, or this would
    // hang/fail on a closed-stdin read instead of succeeding.
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
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
    let encrypted_path = env.file_path("secret.pqe");
    let decrypted_path = env.file_path("secret_dec.txt");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file("some-unrelated-value")
                .to_str()
                .unwrap(),
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
    let encrypted_path = env.file_path("test.pqe");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    assert_eq!(&encrypted[..4], b"PQE4");
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
            expected_encrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
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
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
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
    let encrypted_path = env.file_path("large.pqe");
    let decrypted_path = env.file_path("large_dec.bin");

    // Encrypt
    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("twochunk.pqe");
    let decrypted_path = env.file_path("twochunk_dec.bin");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.create_file("occupied.pqe", SENTINEL);

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("clean.pqe");
    let decrypted_path = env.file_path("clean_dec.bin");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    let encrypted_path = env.file_path("perms.pqe");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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

#[cfg(windows)]
#[test]
fn test_encrypted_output_permissions_windows() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("input.txt", b"permission check");
    let encrypted_path = env.file_path("perms.pqe");

    let output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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

    // Same-volume rename preserves the underlying file object (and thus its
    // security descriptor) on NTFS, so this really asserts the temp file
    // was created with the hardened DACL, mirroring the Unix mode test above.
    let (sids, protected) = windows_dacl::grantees_and_protected(&encrypted_path);
    let expected: std::collections::HashSet<String> =
        [windows_dacl::current_user_sid(), "S-1-5-18".to_string()]
            .into_iter()
            .collect();
    assert_eq!(
        sids, expected,
        "Encrypted output DACL should grant access to exactly {{current user, SYSTEM}}"
    );
    assert!(
        protected,
        "Encrypted output DACL should be protected against inherited ACEs"
    );
}

/// Regression test for partial output on interrupted encryption: a
/// SIGKILL'd run must leave a reclaimable placeholder, not a permanent
/// blocker, and that reclaim must work on the very next attempt with no
/// artificial delay -- proving liveness is determined by the OS lock
/// releasing on process death, not by elapsed time.
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
    let encrypted_path = env.file_path("interrupted.pqe");
    let dir = encrypted_path.parent().unwrap().to_path_buf();

    let mut child = Command::new(pqenc_binary())
        .args([
            "encrypt",
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
    // `interrupted.pqe`, the post-fix build grows a `.tmp.` sibling.
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
        Some(&b"PQE4"[..]),
        "Temp file should hold the real output stream"
    );

    // Follow-up: retry is no longer permanently blocked, and needs no delay
    // or mtime manipulation to prove it: liveness is now determined solely
    // by whether the sibling `<output>.lock` is held, not by elapsed time.
    // `child.wait()` above only returns once the kernel has fully torn down
    // the killed process -- which includes closing every fd, releasing its
    // flock, before `wait()`/`waitpid()` can return -- so the lock is
    // already free and reclaim is immediately available on this very next
    // attempt, with no artificial delay.
    //
    // A second, real (non-killed) encrypt to the exact same output path must
    // now succeed -- the leftover placeholder must be recognized as pqenc's
    // own and reclaimed.
    let retry_input = env.create_file("retry_input.txt", b"retry after SIGKILL must succeed");
    let retry_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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

/// Regression test: two real, concurrently-running pqenc processes
/// targeting the same output path must never race to completion and
/// clobber one another. The second process must fail fast (an immediate,
/// clear contention error), never hang waiting for the first, and never
/// touch the first process's placeholder or temp file.
///
/// Deliberately not `#[cfg(unix)]`-gated -- unlike the SIGKILL test above,
/// this is the one test in the suite that exercises lock contention on
/// Windows' `LockFileEx` path, not just Unix `flock`.
///
/// Process A is fed via an unclosed stdin pipe, the same technique the
/// SIGKILL test above uses, so it stays genuinely mid-operation (holding
/// the output lock) for as long as this test needs, without relying on
/// timing.
#[test]
fn test_second_concurrent_encrypt_to_same_output_is_rejected_not_a_hang() {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let output_path = env.file_path("contended.pqe");

    let mut a = Command::new(pqenc_binary())
        .args([
            "encrypt",
            "-",
            "--output",
            output_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = a.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let block = vec![0xABu8; 64 * 1024];
        while stdin.write_all(&block).is_ok() {}
    });

    // Wait for A's claim to succeed: placeholder creation happens strictly
    // after lock acquisition in program order (see acquire_output_lock and
    // claim_output_and_temp in src/main.rs), so seeing the exact marker
    // here proves the lock is now held.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && fs::read(&output_path).ok().as_deref() != Some(EXPECTED_RESERVATION_MARKER)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        fs::read(&output_path).ok().as_deref(),
        Some(EXPECTED_RESERVATION_MARKER),
        "process A never reached a claimed state"
    );

    // A, now past its claim, creates its own temp file immediately
    // afterward (no fallible step in between in encrypt_file_with_segment_size)
    // -- poll briefly for it, then capture the count before B runs so B's
    // effect can be isolated below.
    let dir = output_path.parent().unwrap().to_path_buf();
    let temp_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < temp_deadline && temp_artifacts(&dir).is_empty() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let temp_count_before_b = temp_artifacts(&dir).len();
    assert!(
        temp_count_before_b > 0,
        "process A should already have its own temp file by now"
    );

    // Process B: targets the SAME output while A is still running. Must
    // fail fast, not hang waiting for A.
    let other_input = env.create_file("b_input.txt", b"process B's content");
    let mut b = Command::new(pqenc_binary())
        .args([
            "encrypt",
            other_input.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let b_deadline = Instant::now() + Duration::from_secs(5);
    let b_status = loop {
        if let Some(status) = b.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < b_deadline,
            "process B did not exit within 5s -- it appears to be blocking on the lock \
            instead of failing fast"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        !b_status.success(),
        "a second concurrent encrypt to the same output must fail"
    );

    // No clobbering: A's placeholder is untouched, and B never even got far
    // enough to create its own temp file -- the temp-file count must be
    // exactly what it was before B ran (A's own, unchanged).
    assert_eq!(
        fs::read(&output_path).unwrap(),
        EXPECTED_RESERVATION_MARKER,
        "process A's placeholder must survive process B's rejected attempt untouched"
    );
    assert_eq!(
        temp_artifacts(&dir).len(),
        temp_count_before_b,
        "process B must fail before creating a temp file"
    );

    a.kill().unwrap();
    a.wait().unwrap();
    let _ = writer.join();
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
    let passphrase_file = write_passphrase_file(pub_path.parent().unwrap(), TEST_PASSPHRASE);
    Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_path.to_str().unwrap(),
            "--private-key",
            priv_path.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
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
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
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

#[cfg(windows)]
#[test]
fn test_generate_keys_key_file_permissions_windows() {
    let env = TempTestEnv::new();
    let pub_path = env.file_path("perm_pub.key");
    let priv_path = env.file_path("perm_priv.key");

    let output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_path.to_str().unwrap(),
            "--private-key",
            priv_path.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (priv_sids, priv_protected) = windows_dacl::grantees_and_protected(&priv_path);
    let expected: std::collections::HashSet<String> =
        [windows_dacl::current_user_sid(), "S-1-5-18".to_string()]
            .into_iter()
            .collect();
    assert_eq!(
        priv_sids, expected,
        "Private key DACL should grant access to exactly {{current user, SYSTEM}}"
    );
    assert!(
        priv_protected,
        "Private key DACL should be protected against inherited ACEs"
    );

    // Deliberately not hardened: the public key is meant to be distributed,
    // so it should keep deferring to the parent directory's ACL.
    let (_pub_sids, pub_protected) = windows_dacl::grantees_and_protected(&pub_path);
    assert!(
        !pub_protected,
        "Public key should not get the owner-only protected DACL"
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

fn extract_all_sha256_fingerprints(output: &str) -> Vec<&str> {
    output
        .match_indices("SHA256:")
        .map(|(start, _)| output[start..].split_whitespace().next().unwrap())
        .collect()
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
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
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
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
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
fn test_fingerprint_rejects_positional_argument() {
    // fingerprint no longer takes a positional at all -- it's --public-key/
    // --private-key only (see the default-key-location tests below).
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let output = Command::new(pqenc_binary())
        .args(["fingerprint", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_fingerprint_rejects_file_that_is_neither_key_type() {
    let env = TempTestEnv::new();
    let not_a_key = env.create_file("not_a_key.txt", b"this is not a pqenc key file");

    let output = Command::new(pqenc_binary())
        .args(["fingerprint", "--public-key", not_a_key.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Not a valid pqenc public or private key file"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_encrypt_prints_recipient_fingerprint_matching_key_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let input_path = env.create_file("input.txt", b"hello");
    let encrypted_path = env.file_path("input.pqe");

    let encrypt_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
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

// ---------------------------------------------------------------------
// Default key location (~/.pqenc/pub.key, ~/.pqenc/priv.key)
//
// Each test below points a fresh `TempDir` at the child process's `HOME`
// (and, harmlessly, `USERPROFILE`) via `set_fake_home`, so none of this
// touches -- or is affected by -- the real developer/CI home directory.
// ---------------------------------------------------------------------

#[test]
fn test_generate_keys_defaults_to_pqenc_dir() {
    let home = TempDir::new().unwrap();
    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pqenc_dir = home.path().join(".pqenc");
    assert!(pqenc_dir.join("pub.key").is_file());
    assert!(pqenc_dir.join("priv.key").is_file());
}

#[cfg(unix)]
#[test]
fn test_generate_keys_default_dir_and_keys_have_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let home = TempDir::new().unwrap();
    // Same umask-in-a-child-shell technique as
    // test_generate_keys_key_file_permissions above: umask(2) is get-and-set,
    // so reading/setting it from a threaded test harness is racy.
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(r#"umask 022; exec "$0" "$@""#)
        .arg(pqenc_binary())
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ]);
    set_fake_home(&mut cmd, home.path());
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pqenc_dir = home.path().join(".pqenc");
    let dir_mode = fs::metadata(&pqenc_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "default key dir should be owner-only, got {:o}",
        dir_mode
    );

    let priv_mode = fs::metadata(pqenc_dir.join("priv.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(priv_mode, 0o600);
    let pub_mode = fs::metadata(pqenc_dir.join("pub.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(pub_mode, 0o644);
}

#[cfg(windows)]
#[test]
fn test_generate_keys_default_dir_and_keys_have_owner_only_permissions_windows() {
    let home = TempDir::new().unwrap();
    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected: std::collections::HashSet<String> =
        [windows_dacl::current_user_sid(), "S-1-5-18".to_string()]
            .into_iter()
            .collect();

    let pqenc_dir = home.path().join(".pqenc");
    let (dir_sids, dir_protected) = windows_dacl::grantees_and_protected(&pqenc_dir);
    assert_eq!(
        dir_sids, expected,
        "default key dir DACL should grant access to exactly {{current user, SYSTEM}}"
    );
    assert!(dir_protected, "default key dir DACL should be protected");

    let (priv_sids, priv_protected) =
        windows_dacl::grantees_and_protected(&pqenc_dir.join("priv.key"));
    assert_eq!(priv_sids, expected);
    assert!(priv_protected);
}

#[test]
fn test_generate_keys_refuses_occupied_default_path() {
    let home = TempDir::new().unwrap();
    let pqenc_dir = home.path().join(".pqenc");
    fs::create_dir_all(&pqenc_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pqenc_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    const SENTINEL: &[u8] = b"an existing key file that must not be touched";
    let priv_key = pqenc_dir.join("priv.key");
    fs::write(&priv_key, SENTINEL).unwrap();

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "must refuse an occupied default path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists"), "stderr: {}", stderr);
    assert_eq!(
        fs::read(&priv_key).unwrap(),
        SENTINEL,
        "existing file was modified"
    );
    assert!(!pqenc_dir.join("pub.key").exists());
}

#[test]
fn test_generate_keys_reuses_existing_default_dir() {
    let home = TempDir::new().unwrap();
    let pqenc_dir = home.path().join(".pqenc");
    fs::create_dir_all(&pqenc_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pqenc_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(pqenc_dir.join("pub.key").is_file());
    assert!(pqenc_dir.join("priv.key").is_file());
}

#[cfg(unix)]
#[test]
fn test_generate_keys_refuses_insecure_existing_default_dir() {
    use std::os::unix::fs::PermissionsExt;

    let home = TempDir::new().unwrap();
    let pqenc_dir = home.path().join(".pqenc");
    fs::create_dir_all(&pqenc_dir).unwrap();
    fs::set_permissions(&pqenc_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "must refuse an insecurely-permissioned existing default dir"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("owner-only") && stderr.contains("0700"),
        "stderr: {}",
        stderr
    );
    assert!(!pqenc_dir.join("pub.key").exists());
    assert!(!pqenc_dir.join("priv.key").exists());
}

#[test]
fn test_encrypt_defaults_to_pqenc_public_key() {
    let home = TempDir::new().unwrap();
    let mut gen_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut gen_cmd, home.path());
    let gen_output = gen_cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    let work_dir = TempDir::new().unwrap();
    let input_path = work_dir.path().join("input.txt");
    fs::write(&input_path, b"hello default key").unwrap();
    let encrypted_path = work_dir.path().join("input.pqe");

    let mut enc_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut enc_cmd, home.path());
    let enc_output = enc_cmd
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        enc_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enc_output.stderr)
    );

    // Decrypt with the explicit private key to confirm it really encrypted
    // to the default public key.
    let decrypted_path = work_dir.path().join("output.txt");
    let priv_key = home.path().join(".pqenc").join("priv.key");
    let dec_output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            write_passphrase_file(work_dir.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(dec_output.status.success());
    assert_eq!(fs::read(&decrypted_path).unwrap(), b"hello default key");
}

#[test]
fn test_encrypt_missing_default_public_key_errors() {
    let home = TempDir::new().unwrap();
    let work_dir = TempDir::new().unwrap();
    let input_path = work_dir.path().join("input.txt");
    fs::write(&input_path, b"hello").unwrap();
    let encrypted_path = work_dir.path().join("input.pqe");

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("pub.key"), "stderr: {}", stderr);
    assert!(stderr.contains("--public-key"), "stderr: {}", stderr);
    assert!(!encrypted_path.exists());
}

#[test]
fn test_decrypt_defaults_to_pqenc_private_key() {
    let home = TempDir::new().unwrap();
    let mut gen_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut gen_cmd, home.path());
    let gen_output = gen_cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    let work_dir = TempDir::new().unwrap();
    let input_path = work_dir.path().join("input.txt");
    fs::write(&input_path, b"hello default private key").unwrap();
    let encrypted_path = work_dir.path().join("input.pqe");
    let pub_key = home.path().join(".pqenc").join("pub.key");
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enc_output.status.success());

    let decrypted_path = work_dir.path().join("output.txt");
    let mut dec_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut dec_cmd, home.path());
    let dec_output = dec_cmd
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--passphrase-file",
            write_passphrase_file(work_dir.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        dec_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dec_output.stderr)
    );
    assert_eq!(
        fs::read(&decrypted_path).unwrap(),
        b"hello default private key"
    );
}

#[test]
fn test_decrypt_missing_default_private_key_errors() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);
    let input_path = env.create_file("input.txt", b"hello");
    let encrypted_path = env.file_path("input.pqe");
    let encrypt_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(encrypt_output.status.success());

    let home = TempDir::new().unwrap();
    let decrypted_path = env.file_path("output.txt");
    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("priv.key"), "stderr: {}", stderr);
    assert!(stderr.contains("--private-key"), "stderr: {}", stderr);
}

#[test]
fn test_fingerprint_defaults_prints_both_keys_when_present() {
    let home = TempDir::new().unwrap();
    let mut gen_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut gen_cmd, home.path());
    // Empty passphrase: plain-text private key, so nothing can prompt here.
    let gen_output = gen_cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), "").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    let mut fp_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut fp_cmd, home.path());
    let output = fp_cmd.args(["fingerprint"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {}", stderr);
    assert!(
        !stderr.contains("Enter passphrase for"),
        "neither key should need a passphrase here; stderr: {}",
        stderr
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fingerprints = extract_all_sha256_fingerprints(&stdout);
    assert_eq!(
        fingerprints.len(),
        2,
        "bare fingerprint should print both default keys; stdout: {}",
        stdout
    );
    assert_eq!(
        fingerprints[0], fingerprints[1],
        "public and private halves of the same keypair must report the same fingerprint"
    );
}

#[test]
fn test_fingerprint_defaults_skips_missing_public_key() {
    let home = TempDir::new().unwrap();
    let pqenc_dir = home.path().join(".pqenc");
    fs::create_dir_all(&pqenc_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pqenc_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Generate a plain-text (no passphrase) keypair elsewhere, then copy only
    // the private key into the default dir, so pub.key is absent there and
    // the resolver must skip it rather than error.
    let env = TempTestEnv::new();
    let (_, priv_key) = env.generate_keys_with_passphrase("");
    fs::copy(&priv_key, pqenc_dir.join("priv.key")).unwrap();

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd.args(["fingerprint"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(extract_all_sha256_fingerprints(&stdout).len(), 1);
}

#[test]
fn test_fingerprint_missing_default_key_errors() {
    let home = TempDir::new().unwrap();
    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, home.path());
    let output = cmd.args(["fingerprint"]).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No default keys found in ~/.pqenc/"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_fingerprint_explicit_flag_disables_defaulting() {
    let home = TempDir::new().unwrap();
    let mut gen_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut gen_cmd, home.path());
    let gen_output = gen_cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), "").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    // A second, unrelated keypair, elsewhere.
    let env = TempTestEnv::new();
    let (_, other_priv_key) = env.generate_keys_with_passphrase("");

    let mut fp_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut fp_cmd, home.path());
    let output = fp_cmd
        .args([
            "fingerprint",
            "--private-key",
            other_priv_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        extract_all_sha256_fingerprints(&stdout).len(),
        1,
        "explicit --private-key must not also pull in the default public key; stdout: {}",
        stdout
    );
    assert!(
        stdout.contains(other_priv_key.to_str().unwrap()),
        "stdout: {}",
        stdout
    );
    let default_pub_key = home.path().join(".pqenc").join("pub.key");
    assert!(
        !stdout.contains(default_pub_key.to_str().unwrap()),
        "stdout should not mention the default public key: {}",
        stdout
    );
}

#[test]
fn test_fingerprint_defaults_uses_supplied_passphrase_for_private_key() {
    let home = TempDir::new().unwrap();
    let mut gen_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut gen_cmd, home.path());
    let gen_output = gen_cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());

    let mut fp_cmd = Command::new(pqenc_binary());
    set_fake_home(&mut fp_cmd, home.path());
    let output = fp_cmd
        .args([
            "fingerprint",
            "--passphrase-file",
            write_passphrase_file(home.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {}", stderr);
    assert!(
        !stderr.contains("Enter passphrase for"),
        "the supplied --passphrase-file should avoid an interactive prompt; stderr: {}",
        stderr
    );
    // The public-key call never receives the passphrase at all when both
    // keys are selected (it's only ever meaningful for the private half),
    // so there's nothing for it to note or ignore.
    assert!(
        !stderr.contains("ignoring supplied passphrase"),
        "the public-key half shouldn't have been given a passphrase to ignore; stderr: {}",
        stderr
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fingerprints = extract_all_sha256_fingerprints(&stdout);
    assert_eq!(fingerprints.len(), 2, "stdout: {}", stdout);
    assert_eq!(fingerprints[0], fingerprints[1]);
}

#[test]
fn test_explicit_key_flags_never_touch_default_location() {
    // A garbage HOME with nothing in it: if any explicit-path call site
    // accidentally consulted the default location, it would fail here.
    let home = TempDir::new().unwrap();
    let bogus_home = home.path().join("does-not-exist");

    let env = TempTestEnv::new();
    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, &bogus_home);
    let output = cmd
        .args([
            "generate-keys",
            "--public-key",
            env.file_path("explicit_pub.key").to_str().unwrap(),
            "--private-key",
            env.file_path("explicit_priv.key").to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "explicit -p/-s must not require a resolvable HOME; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(env.file_path("explicit_pub.key").is_file());
    assert!(env.file_path("explicit_priv.key").is_file());
}

#[cfg(unix)]
#[test]
fn test_generate_keys_rejects_non_utf8_home() {
    use std::os::unix::ffi::OsStringExt;

    // A lone 0xFF byte is never valid UTF-8 in any position, so `HOME` fails
    // to convert regardless of what else surrounds it.
    let bogus_home = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);
    // Unrelated to `bogus_home` -- just a real place to put a passphrase
    // file, in case key-path resolution order ever changes and this
    // actually gets read.
    let real_dir = TempDir::new().unwrap();

    let mut cmd = Command::new(pqenc_binary());
    set_fake_home(&mut cmd, std::path::Path::new(&bogus_home));
    let output = cmd
        .args([
            "generate-keys",
            "--passphrase-file",
            write_passphrase_file(real_dir.path(), TEST_PASSPHRASE)
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "must refuse a non-UTF-8 $HOME rather than silently using a corrupted path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not valid UTF-8"), "stderr: {}", stderr);
}

// ---------------------------------------------------------------------
// --passphrase-file (replaced --passphrase)
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn test_passphrase_file_rejects_group_readable_file() {
    use std::os::unix::fs::PermissionsExt;

    let env = TempTestEnv::new();
    let passphrase_path = env.file_path("leaky_passphrase.txt");
    fs::write(&passphrase_path, TEST_PASSPHRASE).unwrap();
    fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o644)).unwrap();

    let output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            env.file_path("leaky_pub.key").to_str().unwrap(),
            "--private-key",
            env.file_path("leaky_priv.key").to_str().unwrap(),
            "--passphrase-file",
            passphrase_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "must refuse a group/world-readable passphrase file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("owner-only"), "stderr: {}", stderr);
    assert!(!env.file_path("leaky_pub.key").exists());
    assert!(!env.file_path("leaky_priv.key").exists());
}

#[test]
fn test_passphrase_file_dev_null_is_exempt_from_permission_check() {
    let env = TempTestEnv::new();
    let pub_key = env.file_path("null_pub.key");
    let priv_key = env.file_path("null_priv.key");

    // Windows has no /dev/null, and no permission check to exempt it from in
    // the first place -- NUL just naturally reads as empty either way.
    let devnull = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            devnull,
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("stored in plain text"),
        "stdout: {}",
        stdout
    );
}

#[test]
fn test_passphrase_file_supports_stdin() {
    let env = TempTestEnv::new();
    let pub_key = env.file_path("stdin_pub.key");
    let priv_key = env.file_path("stdin_priv.key");

    let mut child = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(TEST_PASSPHRASE.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Confirm the key really was encrypted with TEST_PASSPHRASE by round
    // tripping through it.
    let input_path = env.create_file("stdin_test.txt", b"stdin passphrase works");
    let encrypted_path = env.file_path("stdin_test.pqe");
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enc_output.status.success());

    let decrypted_path = env.file_path("stdin_test_dec.txt");
    let dec_output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        dec_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dec_output.stderr)
    );
    assert_eq!(
        fs::read(&decrypted_path).unwrap(),
        b"stdin passphrase works"
    );
}

#[test]
fn test_passphrase_file_strips_trailing_newline() {
    let env = TempTestEnv::new();
    let pub_key = env.file_path("nl_pub.key");
    let priv_key = env.file_path("nl_priv.key");

    // As `echo passphrase > file` would produce: the value plus a trailing \n.
    let passphrase_path = env.file_path("nl_passphrase.txt");
    fs::write(&passphrase_path, format!("{}\n", TEST_PASSPHRASE)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let gen_output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            passphrase_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        gen_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&gen_output.stderr)
    );

    // Decrypting with the passphrase *without* the trailing newline must
    // work -- proving the newline byte isn't part of the stored passphrase.
    let input_path = env.create_file("nl_test.txt", b"newline stripped");
    let encrypted_path = env.file_path("nl_test.pqe");
    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enc_output.status.success());

    let decrypted_path = env.file_path("nl_test_dec.txt");
    let dec_output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.passphrase_file(TEST_PASSPHRASE).to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        dec_output.status.success(),
        "decrypting with the passphrase minus its trailing newline should \
         work only if generate-keys also stripped it; stderr: {}",
        String::from_utf8_lossy(&dec_output.stderr)
    );
    assert_eq!(fs::read(&decrypted_path).unwrap(), b"newline stripped");
}

#[test]
fn test_passphrase_flag_no_longer_exists() {
    let env = TempTestEnv::new();
    let output = Command::new(pqenc_binary())
        .args([
            "generate-keys",
            "--public-key",
            env.file_path("gone_pub.key").to_str().unwrap(),
            "--private-key",
            env.file_path("gone_priv.key").to_str().unwrap(),
            "--passphrase",
            "somevalue",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "the old --passphrase flag should no longer be recognized"
    );
    assert!(!env.file_path("gone_pub.key").exists());
}

// ---------------------------------------------------------------------
// --passphrase-file is resolved lazily, only once actually needed (not
// eagerly in `run()`) -- so a bad/missing passphrase file never breaks a
// plain-text key or a public-key-only fingerprint, and never blocks
// reading stdin before cheaper checks (verify preflight) get a chance to
// fail fast.
// ---------------------------------------------------------------------

#[test]
fn test_decrypt_unencrypted_key_ignores_missing_passphrase_file() {
    let env = TempTestEnv::new();
    let (pub_key, priv_key) = env.generate_keys_with_passphrase("");

    let data = b"plain text key data";
    let input_path = env.create_file("plain.txt", data);
    let encrypted_path = env.file_path("plain.pqe");
    let decrypted_path = env.file_path("plain_dec.txt");

    let enc_output = Command::new(pqenc_binary())
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            encrypted_path.to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enc_output.status.success());

    // A --passphrase-file that doesn't exist at all: must still succeed,
    // since a plain-text private key never needs it.
    let output = Command::new(pqenc_binary())
        .args([
            "decrypt",
            encrypted_path.to_str().unwrap(),
            "--output",
            decrypted_path.to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            env.file_path("does_not_exist.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "a plain-text key must ignore an unreadable passphrase file entirely; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&decrypted_path).unwrap(), data);
}

#[test]
fn test_fingerprint_public_key_ignores_missing_passphrase_file() {
    let env = TempTestEnv::new();
    let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    let output = Command::new(pqenc_binary())
        .args([
            "fingerprint",
            "--public-key",
            pub_key.to_str().unwrap(),
            "--passphrase-file",
            env.file_path("does_not_exist.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fingerprinting a public key must ignore an unreadable passphrase file entirely; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_decrypt_does_not_block_on_stdin_passphrase_when_verify_fails_first() {
    let env = TempTestEnv::new();
    let (_, priv_key) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

    // Invalid magic bytes: verify_open_file must reject this immediately,
    // before decrypt ever touches the private key or the passphrase.
    let mut bad_data = b"XXX1".to_vec();
    bad_data.extend_from_slice(&[0u8; 2000]);
    let bad_input = env.create_file("bad.pqe", &bad_data);

    let mut child = Command::new(pqenc_binary())
        .args([
            "decrypt",
            bad_input.to_str().unwrap(),
            "--output",
            env.file_path("out.bin").to_str().unwrap(),
            "--private-key",
            priv_key.to_str().unwrap(),
            "--passphrase-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Take ownership of the write end ourselves and keep it alive -- never
    // written to, never dropped -- for the rest of this test. child.stdin
    // is now None, so wait_with_output below won't auto-close anything (it
    // only closes a handle it still owns); if decrypt ever regresses to
    // resolving --passphrase-file before the verify preflight, it would
    // block reading this genuinely-still-open, empty pipe forever.
    let _keep_stdin_open = child.stdin.take().unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    let output = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect(
            "decrypt must fail fast on a corrupted input file rather than \
             block reading --passphrase-file -",
        )
        .unwrap();

    assert!(
        !output.status.success(),
        "a corrupted, non-pqenc input file must fail verification"
    );
}
