mod helpers;
use helpers::{TempTestEnv, TestData, TEST_PASSPHRASE};
use proptest::prelude::*;
use std::fs;
use std::process::Command;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn test_encrypt_decrypt_roundtrip_random_data(
        size in 1usize..1024*1024 // Test sizes from 1 byte to 1 MB
    ) {
        let env = TempTestEnv::new();
        let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for size {}", size);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_passphrase(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSPHRASE
        );

        prop_assert!(decrypt_result.is_ok(), "Decryption failed for size {}", size);

        let decrypted = fs::read(&decrypted_path).unwrap();
        prop_assert_eq!(decrypted, data.plaintext, "Data mismatch for size {}", size);
    }
}

// Since `pqenc encrypt` always appends a checksum trailer now, every
// round trip below through the real CLI also doubles as regression coverage
// for decrypt_file's trailer-aware body-length math: test_chunk_boundaries
// exercises sizes that are exact multiples of CHUNK_SIZE (the "last chunk is
// exactly encrypted_chunk_size" case), and test_near_chunk_boundaries
// exercises sizes just past a boundary (the "last chunk is shorter than
// encrypted_chunk_size" case, the more common one). See
// tests/integration_tests.rs for a dedicated, non-random test pinned to
// exactly 2*CHUNK_SIZE for the same reason with an easier-to-debug failure.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_chunk_boundaries(
        chunks in 1usize..20 // Test 1 to 20 chunks
    ) {
        let env = TempTestEnv::new();
        let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

        let chunk_size = 64 * 1024;
        let size = chunks * chunk_size;
        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for {} chunks", chunks);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_passphrase(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSPHRASE
        );

        prop_assert!(decrypt_result.is_ok(), "Decryption failed for {} chunks", chunks);

        let decrypted = fs::read(&decrypted_path).unwrap();
        prop_assert_eq!(decrypted, data.plaintext, "Data mismatch for {} chunks", chunks);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_near_chunk_boundaries(
        offset in 0usize..1024 // Vary size around chunk boundary
    ) {
        let env = TempTestEnv::new();
        let (pub_key, _) = env.generate_keys_with_passphrase(TEST_PASSPHRASE);

        let chunk_size = 64 * 1024;
        let size = chunk_size + offset;
        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for size {}", size);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_passphrase(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSPHRASE
        );

        prop_assert!(decrypt_result.is_ok(), "Decryption failed for size {}", size);

        let decrypted = fs::read(&decrypted_path).unwrap();
        prop_assert_eq!(decrypted.len(), data.plaintext.len(), "Length mismatch for size {}", size);
        prop_assert_eq!(decrypted, data.plaintext, "Data mismatch for size {}", size);
    }
}
