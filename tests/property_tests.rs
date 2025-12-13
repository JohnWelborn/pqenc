mod helpers;
use helpers::{TestData, TempTestEnv, TEST_PASSWORD};
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
        let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(&["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for size {}", size);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_password(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSWORD
        );

        prop_assert!(decrypt_result.is_ok(), "Decryption failed for size {}", size);

        let decrypted = fs::read(&decrypted_path).unwrap();
        prop_assert_eq!(decrypted, data.plaintext, "Data mismatch for size {}", size);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_chunk_boundaries(
        chunks in 1usize..20 // Test 1 to 20 chunks
    ) {
        let env = TempTestEnv::new();
        let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

        let chunk_size = 64 * 1024;
        let size = chunks * chunk_size;
        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(&["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for {} chunks", chunks);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_password(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSWORD
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
        let (pub_key, _) = env.generate_keys_with_password(TEST_PASSWORD);

        let chunk_size = 64 * 1024;
        let size = chunk_size + offset;
        let data = TestData::random(size);
        let input_path = env.create_file("input.bin", &data.plaintext);
        let encrypted_path = env.file_path("encrypted.enc");
        let decrypted_path = env.file_path("decrypted.bin");

        // Encrypt
        let output = Command::new(pqenc_binary())
            .args(&["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        prop_assert!(output.status.success(), "Encryption failed for size {}", size);

        // Decrypt
        let decrypt_result = env.decrypt_file_with_password(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            TEST_PASSWORD
        );

        prop_assert!(decrypt_result.is_ok(), "Decryption failed for size {}", size);

        let decrypted = fs::read(&decrypted_path).unwrap();
        prop_assert_eq!(decrypted.len(), data.plaintext.len(), "Length mismatch for size {}", size);
        prop_assert_eq!(decrypted, data.plaintext, "Data mismatch for size {}", size);
    }
}
