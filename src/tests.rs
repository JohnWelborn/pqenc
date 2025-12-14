    use super::*;

    // PEM encoding/decoding tests
    mod pem_tests {
        use super::*;

        #[test]
        fn test_pem_encode_decode_roundtrip() {
            let original = b"test data 12345";
            let encoded = pem_encode(original, PEM_PUB_BEGIN, PEM_PUB_END);

            assert!(encoded.contains(PEM_PUB_BEGIN));
            assert!(encoded.contains(PEM_PUB_END));

            let decoded = pem_decode(&encoded, PEM_PUB_BEGIN, PEM_PUB_END).unwrap();
            assert_eq!(decoded, original);
        }

        #[test]
        fn test_pem_encode_line_wrapping() {
            let data = vec![0xFF; 100];
            let encoded = pem_encode(&data, PEM_PUB_BEGIN, PEM_PUB_END);

            let lines: Vec<&str> = encoded.lines().collect();
            for line in &lines[1..lines.len()-1] {
                assert!(line.len() <= 64);
            }
        }

        #[test]
        fn test_pem_decode_with_whitespace() {
            let data = b"test";
            let encoded = pem_encode(data, PEM_PUB_BEGIN, PEM_PUB_END);
            let messy = encoded.replace('\n', "\r\n  \n  ");
            let decoded = pem_decode(&messy, PEM_PUB_BEGIN, PEM_PUB_END).unwrap();
            assert_eq!(decoded, data);
        }

        #[test]
        fn test_pem_decode_missing_header() {
            let result = pem_decode("invalid pem", PEM_PUB_BEGIN, PEM_PUB_END);
            assert!(result.is_err());
        }

        #[test]
        fn test_pem_large_data() {
            let large = vec![0x42; 10_000];
            let encoded = pem_encode(&large, PEM_PUB_BEGIN, PEM_PUB_END);
            let decoded = pem_decode(&encoded, PEM_PUB_BEGIN, PEM_PUB_END).unwrap();
            assert_eq!(decoded, large);
        }
    }

    // Password derivation tests
    mod password_tests {
        use super::*;

        #[test]
        fn test_derive_key_deterministic() {
            let password = b"test-password";
            let salt = [42u8; ARGON2_SALT_SIZE];

            let key1 = derive_key_from_password(password, &salt).unwrap();
            let key2 = derive_key_from_password(password, &salt).unwrap();

            assert_eq!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_key_different_salts() {
            let password = b"test-password";
            let salt1 = [1u8; ARGON2_SALT_SIZE];
            let salt2 = [2u8; ARGON2_SALT_SIZE];

            let key1 = derive_key_from_password(password, &salt1).unwrap();
            let key2 = derive_key_from_password(password, &salt2).unwrap();

            assert_ne!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_key_empty_password() {
            let salt = [0u8; ARGON2_SALT_SIZE];
            let result = derive_key_from_password(b"", &salt);
            assert!(result.is_err());
        }

        #[test]
        fn test_derive_key_output_length() {
            let password = b"password";
            let salt = [0u8; ARGON2_SALT_SIZE];
            let key = derive_key_from_password(password, &salt).unwrap();
            assert_eq!(key.data.len(), ARGON2_KEY_LENGTH);
        }
    }

    // Private key encryption/decryption tests
    mod key_encryption_tests {
        use super::*;

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let original = b"secret private key data";
            let password = b"secure-password";

            let encrypted = encrypt_private_key(original, password).unwrap();
            let decrypted = decrypt_private_key(&encrypted, password).unwrap();

            assert_eq!(decrypted.data, original);
        }

        #[test]
        fn test_encrypt_produces_different_output() {
            let key = b"private key";
            let password = b"password";

            let enc1 = encrypt_private_key(key, password).unwrap();
            let enc2 = encrypt_private_key(key, password).unwrap();

            assert_ne!(enc1, enc2);
        }

        #[test]
        fn test_decrypt_wrong_password() {
            let key = b"secret";
            let password = b"correct";
            let wrong = b"wrong";

            let encrypted = encrypt_private_key(key, password).unwrap();
            let result = decrypt_private_key(&encrypted, wrong);

            assert!(result.is_err());
        }

        #[test]
        fn test_decrypt_corrupted() {
            let key = b"secret";
            let password = b"password";

            let mut encrypted = encrypt_private_key(key, password).unwrap();
            let pos = encrypted.len() / 2;
            encrypted[pos] ^= 0xFF;

            let result = decrypt_private_key(&encrypted, password);
            assert!(result.is_err());
        }
    }

    // Composite key parsing tests
    mod key_parsing_tests {
        use super::*;

        #[test]
        fn test_parse_public_key_valid() {
            let mlkem_pk = vec![0x42; 1568];
            let x25519_pk = [0x33; 32];

            let mut composite = Vec::new();
            composite.extend_from_slice(&(mlkem_pk.len() as u32).to_be_bytes());
            composite.extend_from_slice(&mlkem_pk);
            composite.extend_from_slice(&x25519_pk);

            let (parsed_mlkem, parsed_x25519) =
                parse_public_composite_key(&composite).unwrap();

            assert_eq!(parsed_mlkem, mlkem_pk);
            assert_eq!(parsed_x25519, x25519_pk);
        }

        #[test]
        fn test_parse_public_key_too_short() {
            let short_data = vec![0u8; 10];
            let result = parse_public_composite_key(&short_data);
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_public_key_invalid_length() {
            let mut data = Vec::new();
            data.extend_from_slice(&(0u32).to_be_bytes());
            data.extend_from_slice(&[0u8; 32]);

            let result = parse_public_composite_key(&data);
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_private_key_valid() {
            let mlkem_sk = vec![0x42; 3168];
            let x25519_sk = [0x33; 32];

            let mut composite = Vec::new();
            composite.extend_from_slice(&(mlkem_sk.len() as u32).to_be_bytes());
            composite.extend_from_slice(&mlkem_sk);
            composite.extend_from_slice(&x25519_sk);

            let (parsed_mlkem, parsed_x25519) =
                parse_private_composite_key(&composite).unwrap();

            assert_eq!(parsed_mlkem.data, mlkem_sk);
            assert_eq!(parsed_x25519.data.as_slice(), &x25519_sk);
        }
    }

    // AES key derivation tests
    mod aes_tests {
        use super::*;

        #[test]
        fn test_derive_aes_key_deterministic() {
            let secret = vec![0x42; SHARED_SECRET_SIZE];
            let salt = [0x33; SALT_SIZE];

            let key1 = derive_aes_key(&secret, &salt).unwrap();
            let key2 = derive_aes_key(&secret, &salt).unwrap();

            assert_eq!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_aes_key_different_salts() {
            let secret = vec![0x42; SHARED_SECRET_SIZE];
            let salt1 = [0x01; SALT_SIZE];
            let salt2 = [0x02; SALT_SIZE];

            let key1 = derive_aes_key(&secret, &salt1).unwrap();
            let key2 = derive_aes_key(&secret, &salt2).unwrap();

            assert_ne!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_aes_key_invalid_size() {
            let short = vec![0x42; 32];
            let salt = [0x33; SALT_SIZE];

            let result = derive_aes_key(&short, &salt);
            assert!(result.is_err());
        }

        #[test]
        fn test_derive_aes_key_output_size() {
            let secret = vec![0x42; SHARED_SECRET_SIZE];
            let salt = [0x33; SALT_SIZE];

            let key = derive_aes_key(&secret, &salt).unwrap();
            assert_eq!(key.data.len(), AES_KEY_SIZE);
        }
    }

    // Nonce generation tests
    mod nonce_tests {
        use super::*;

        #[test]
        fn test_get_nonce_sequential() {
            let base = [0u8; NONCE_SIZE];

            let nonce0 = get_nonce(&base, 0).unwrap();
            let nonce1 = get_nonce(&base, 1).unwrap();
            let nonce2 = get_nonce(&base, 2).unwrap();

            assert_ne!(nonce0.as_slice(), nonce1.as_slice());
            assert_ne!(nonce1.as_slice(), nonce2.as_slice());
        }

        #[test]
        fn test_get_nonce_deterministic() {
            let base = [0x42; NONCE_SIZE];
            let counter = 100;

            let nonce1 = get_nonce(&base, counter).unwrap();
            let nonce2 = get_nonce(&base, counter).unwrap();

            assert_eq!(nonce1.as_slice(), nonce2.as_slice());
        }

        #[test]
        fn test_get_nonce_large_values() {
            // Test that large but valid values work
            let base = [0xFF; NONCE_SIZE];
            let huge = u64::MAX;

            // This should succeed because u128 can hold this
            let result = get_nonce(&base, huge);
            assert!(result.is_ok());
        }
    }
