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

    // Passphrase derivation tests
    mod passphrase_tests {
        use super::*;

        #[test]
        fn test_derive_key_deterministic() {
            let passphrase = b"test-passphrase";
            let salt = [42u8; ARGON2_SALT_SIZE];

            let key1 = derive_key_from_passphrase(passphrase, &salt).unwrap();
            let key2 = derive_key_from_passphrase(passphrase, &salt).unwrap();

            assert_eq!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_key_different_salts() {
            let passphrase = b"test-passphrase";
            let salt1 = [1u8; ARGON2_SALT_SIZE];
            let salt2 = [2u8; ARGON2_SALT_SIZE];

            let key1 = derive_key_from_passphrase(passphrase, &salt1).unwrap();
            let key2 = derive_key_from_passphrase(passphrase, &salt2).unwrap();

            assert_ne!(key1.data, key2.data);
        }

        #[test]
        fn test_derive_key_empty_passphrase() {
            let salt = [0u8; ARGON2_SALT_SIZE];
            let result = derive_key_from_passphrase(b"", &salt);
            assert!(result.is_err());
        }

        #[test]
        fn test_derive_key_output_length() {
            let passphrase = b"passphrase";
            let salt = [0u8; ARGON2_SALT_SIZE];
            let key = derive_key_from_passphrase(passphrase, &salt).unwrap();
            assert_eq!(key.data.len(), ARGON2_KEY_LENGTH);
        }
    }

    // Private key encryption/decryption tests
    mod key_encryption_tests {
        use super::*;

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let original = b"secret private key data";
            let passphrase = b"secure-passphrase";

            let encrypted = encrypt_private_key(original, passphrase).unwrap();
            let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

            assert_eq!(decrypted.data, original);
        }

        #[test]
        fn test_encrypt_produces_different_output() {
            let key = b"private key";
            let passphrase = b"passphrase";

            let enc1 = encrypt_private_key(key, passphrase).unwrap();
            let enc2 = encrypt_private_key(key, passphrase).unwrap();

            assert_ne!(enc1, enc2);
        }

        #[test]
        fn test_decrypt_wrong_passphrase() {
            let key = b"secret";
            let passphrase = b"correct";
            let wrong = b"wrong";

            let encrypted = encrypt_private_key(key, passphrase).unwrap();
            let result = decrypt_private_key(&encrypted, wrong);

            assert!(result.is_err());
        }

        #[test]
        fn test_decrypt_corrupted() {
            let key = b"secret";
            let passphrase = b"passphrase";

            let mut encrypted = encrypt_private_key(key, passphrase).unwrap();
            let pos = encrypted.len() / 2;
            encrypted[pos] ^= 0xFF;

            let result = decrypt_private_key(&encrypted, passphrase);
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
        fn test_parse_public_key_rejects_wrong_length() {
            // One byte over the exact ML-KEM-1024 size. Previously accepted
            // by the old `kem_len <= 8000` bound; must now be rejected.
            let mlkem_pk = vec![0x42; MLKEM1024_PUBLIC_KEY_SIZE + 1];
            let x25519_pk = [0x33; 32];

            let mut composite = Vec::new();
            composite.extend_from_slice(&(mlkem_pk.len() as u32).to_be_bytes());
            composite.extend_from_slice(&mlkem_pk);
            composite.extend_from_slice(&x25519_pk);

            let result = parse_public_composite_key(&composite);
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

        #[test]
        fn test_parse_private_key_rejects_wrong_length() {
            // One byte over the exact ML-KEM-1024 size. Previously accepted
            // by the old `kem_len <= 10000` bound; must now be rejected.
            let mlkem_sk = vec![0x42; MLKEM1024_PRIVATE_KEY_SIZE + 1];
            let x25519_sk = [0x33; 32];

            let mut composite = Vec::new();
            composite.extend_from_slice(&(mlkem_sk.len() as u32).to_be_bytes());
            composite.extend_from_slice(&mlkem_sk);
            composite.extend_from_slice(&x25519_sk);

            let result = parse_private_composite_key(&composite);
            assert!(result.is_err());
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
            // Test that large but valid values work: zero base nonce leaves full
            // 96-bit range available, so u64::MAX fits without overflow
            let base = [0u8; NONCE_SIZE];
            let huge = u64::MAX;

            let result = get_nonce(&base, huge);
            assert!(result.is_ok());
        }
    }

    // Fingerprint and randomart tests
    mod fingerprint_tests {
        use super::*;

        #[test]
        fn test_format_fingerprint_matches_ssh_keygen_style() {
            let digest = [0u8; 32];
            let formatted = format_fingerprint(&digest);

            assert!(formatted.starts_with("SHA256:"));
            assert!(!formatted.contains('='), "must be unpadded base64");
            assert_eq!(
                formatted,
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            );
        }

        #[test]
        fn test_compute_fingerprint_deterministic_and_sensitive_to_input() {
            let a = compute_fingerprint(b"same input");
            let b = compute_fingerprint(b"same input");
            let c = compute_fingerprint(b"different input");

            assert_eq!(a, b);
            assert_ne!(a, c);
        }

        #[test]
        fn test_randomart_deterministic_and_well_formed() {
            let digest = [0x42u8; 32];
            let art1 = randomart(&digest, "ML-KEM-1024", "SHA256");
            let art2 = randomart(&digest, "ML-KEM-1024", "SHA256");
            assert_eq!(art1, art2, "same digest must produce identical randomart");

            let lines: Vec<&str> = art1.lines().collect();
            assert_eq!(lines.len(), 11, "top border + 9 rows + bottom border");
            for line in &lines {
                assert_eq!(line.chars().count(), 19, "every line is 19 chars wide: {}", line);
            }
            assert!(lines[0].starts_with("+--[ML-KEM-1024]--") && lines[0].ends_with('+'));
            assert!(lines[10].starts_with("+----[SHA256]-----") && lines[10].ends_with('+'));
            for row in &lines[1..10] {
                assert!(row.starts_with('|') && row.ends_with('|'));
            }
        }

        #[test]
        fn test_randomart_differs_for_different_digests() {
            let art_a = randomart(&[0u8; 32], "ML-KEM-1024", "SHA256");
            let art_b = randomart(&[0xFFu8; 32], "ML-KEM-1024", "SHA256");
            assert_ne!(art_a, art_b);
        }

        #[test]
        fn test_extract_public_from_private_matches_generated_composite() {
            // Build a synthetic ML-KEM secret key with a known "ek" embedded at
            // the FIPS 203 offset, and a known X25519 secret, then verify
            // reconstruction pulls out exactly the same public key bytes
            // `generate_keys` would have stored.
            use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

            let mut mlkem_sk = vec![0u8; MLKEM1024_PRIVATE_KEY_SIZE];
            let embedded_ek = vec![0xABu8; MLKEM1024_PUBLIC_KEY_SIZE];
            mlkem_sk[MLKEM1024_PUBLIC_KEY_OFFSET..MLKEM1024_PUBLIC_KEY_OFFSET + MLKEM1024_PUBLIC_KEY_SIZE]
                .copy_from_slice(&embedded_ek);

            let x25519_secret = StaticSecret::from([7u8; 32]);
            let expected_x25519_pk = X25519PublicKey::from(&x25519_secret);
            let x25519_sk_bytes = x25519_secret.to_bytes();

            let composite_pub = extract_public_from_private(&mlkem_sk, &x25519_sk_bytes).unwrap();
            let (mlkem_pk, x25519_pk) = parse_public_composite_key(&composite_pub).unwrap();

            assert_eq!(mlkem_pk, embedded_ek);
            assert_eq!(x25519_pk, *expected_x25519_pk.as_bytes());
        }

        #[test]
        fn test_extract_public_from_private_rejects_wrong_size() {
            let short_sk = vec![0u8; 100];
            let x25519_sk = [0u8; 32];
            assert!(extract_public_from_private(&short_sk, &x25519_sk).is_err());
        }
    }

    // Pure unit tests for the PQE2 TLV/metadata/output-resolution helpers --
    // no crypto or file I/O involved.
    mod metadata_tests {
        use super::*;

        #[test]
        fn test_tlv_roundtrip() {
            let value = b"hello";
            let encoded = encode_tlv_fields(&[(0x01, value)]);
            let parsed = parse_tlv_fields(&encoded).unwrap();
            assert_eq!(parsed, vec![(0x01, &value[..])]);
        }

        #[test]
        fn test_tlv_empty() {
            let encoded = encode_tlv_fields(&[]);
            assert!(encoded.is_empty());
            assert_eq!(parse_tlv_fields(&encoded).unwrap(), Vec::new());
        }

        #[test]
        fn test_tlv_multiple_fields_including_unknown_are_all_parsed() {
            // Forward compatibility: an unrecognized field ID must not
            // prevent parsing of the fields around it.
            let encoded = encode_tlv_fields(&[
                (0xFE, b"future"),
                (0x01, b"known"),
            ]);
            let parsed = parse_tlv_fields(&encoded).unwrap();
            assert_eq!(parsed, vec![(0xFE, &b"future"[..]), (0x01, &b"known"[..])]);
        }

        #[test]
        fn test_tlv_rejects_truncated_length_prefix() {
            let bad = vec![0x01, 0x00, 0x00]; // field id + partial length prefix
            assert!(parse_tlv_fields(&bad).is_err());
        }

        #[test]
        fn test_tlv_rejects_truncated_value() {
            let mut bad = vec![0x01];
            bad.extend_from_slice(&10u32.to_be_bytes()); // claims 10 bytes
            bad.extend_from_slice(b"short"); // only 5 provided
            assert!(parse_tlv_fields(&bad).is_err());
        }

        #[test]
        fn test_timestamp_roundtrip() {
            let t = filetime::FileTime::from_unix_time(1_700_000_000, 123_456_789);
            let encoded = encode_timestamp(t);
            let decoded = decode_timestamp(&encoded).unwrap();
            assert_eq!(decoded, t);
        }

        #[test]
        fn test_timestamp_rejects_wrong_length() {
            assert!(decode_timestamp(&[0u8; 11]).is_err());
            assert!(decode_timestamp(&[0u8; 13]).is_err());
        }

        #[test]
        fn test_decode_metadata_plaintext_skips_unknown_field() {
            // The unknown field (0xFE) sits between two known ones, proving
            // it doesn't disrupt parsing of its neighbors -- the core
            // forward-compatibility guarantee.
            let mtime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(100, 0));
            let atime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(200, 0));
            let plaintext = encode_tlv_fields(&[
                (METADATA_FIELD_FILENAME, b"report.pdf"),
                (0xFE, b"unrecognized"),
                (METADATA_FIELD_MTIME, &mtime_bytes),
                (METADATA_FIELD_ATIME, &atime_bytes),
            ]);

            let decoded = decode_metadata_plaintext(&plaintext).unwrap();
            assert_eq!(decoded.filename.as_deref(), Some("report.pdf"));
            assert_eq!(decoded.mtime, Some(filetime::FileTime::from_unix_time(100, 0)));
            assert_eq!(decoded.atime, Some(filetime::FileTime::from_unix_time(200, 0)));
        }

        #[test]
        fn test_encode_metadata_plaintext_none_is_empty() {
            assert!(encode_metadata_plaintext(None).is_empty());
        }

        #[test]
        fn test_sanitize_rejects_traversal_and_separators() {
            for bad in ["..", ".", "", "../evil", "../../evil", "/etc/passwd",
                        "a/b", "a\\b", "..\\evil", "a\0b"] {
                assert!(sanitize_embedded_filename(bad).is_none(), "should reject {:?}", bad);
            }
        }

        #[test]
        fn test_sanitize_accepts_ordinary_filenames() {
            for good in ["report.pdf", "my archive.tar.gz", "IMG_0001.JPG", "2024-01-01T12:00:00.txt"] {
                assert_eq!(sanitize_embedded_filename(good).as_deref(), Some(good));
            }
        }

        #[test]
        fn test_resolve_encrypt_output_passthrough() {
            assert_eq!(
                resolve_encrypt_output("in.txt", Some("explicit.pqe".to_string())).unwrap(),
                "explicit.pqe"
            );
        }

        #[test]
        fn test_resolve_encrypt_output_defaults_to_pqe_suffix() {
            assert_eq!(resolve_encrypt_output("in.txt", None).unwrap(), "in.txt.pqe");
        }

        #[test]
        fn test_resolve_encrypt_output_rejects_stdin_without_explicit_output() {
            assert!(resolve_encrypt_output("-", None).is_err());
            assert!(resolve_encrypt_output("/dev/stdin", None).is_err());
        }

        #[test]
        fn test_resolve_decrypt_output_prefers_sanitized_embedded_filename() {
            let resolved = resolve_decrypt_output("/tmp/archive/backup.pqe", Some("report.pdf")).unwrap();
            assert_eq!(resolved, "/tmp/archive/report.pdf");
        }

        #[test]
        fn test_resolve_decrypt_output_falls_back_when_embedded_name_unsafe() {
            let resolved = resolve_decrypt_output("/tmp/backup.pqe", Some("../../evil")).unwrap();
            assert_eq!(resolved, "/tmp/backup");
            assert!(!resolved.contains(".."));
        }

        #[test]
        fn test_resolve_decrypt_output_strips_pqe_suffix_without_metadata() {
            assert_eq!(resolve_decrypt_output("/tmp/x.pqe", None).unwrap(), "/tmp/x");
        }

        #[test]
        fn test_resolve_decrypt_output_requires_explicit_output_without_suffix_or_metadata() {
            assert!(resolve_decrypt_output("/tmp/x.bin", None).is_err());
        }
    }

    // Builds a real, cryptographically valid .pqe file plus a matching
    // plain-text private key PEM, entirely from this module's own internals
    // -- bypassing `encrypt_file`. This is what lets the tests below inject
    // header/metadata field values `encrypt_file` itself could never
    // produce (an unrecognized TLV field ID, or a malicious embedded
    // filename containing ".."), which is exactly what's needed to test
    // forward compatibility and the filename sanitizer end-to-end.
    fn build_test_pqe_file(
        magic: &[u8],
        extension_fields: &[(u8, &[u8])],
        metadata_fields: &[(u8, &[u8])],
        plaintext: &[u8],
    ) -> (Vec<u8>, String) {
        use x25519_dalek::{PublicKey as X25519PublicKey, EphemeralSecret, StaticSecret};
        use sha2::Digest;

        // Recipient keypair
        let mut key_gen_randomness = [0u8; 64];
        rand::rng().fill_bytes(&mut key_gen_randomness);
        let key_pair = mlkem1024::generate_key_pair(key_gen_randomness);
        let (mlkem_secret, mlkem_public) = key_pair.into_parts();

        let mut x25519_secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut x25519_secret_bytes);
        let x25519_secret = StaticSecret::from(x25519_secret_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Plain-text private key PEM (no passphrase), so tests can call
        // decrypt_file directly without a passphrase prompt.
        let mut composite_priv = Vec::new();
        let mlkem_sk_bytes = mlkem_secret.as_slice();
        composite_priv.extend_from_slice(&(mlkem_sk_bytes.len() as u32).to_be_bytes());
        composite_priv.extend_from_slice(mlkem_sk_bytes);
        composite_priv.extend_from_slice(x25519_secret.to_bytes().as_ref());
        let priv_pem = pem_encode(&composite_priv, PEM_PRIV_BEGIN, PEM_PRIV_END);

        // Encapsulate/DH exactly as encrypt_file does
        let mut encaps_randomness = [0u8; 32];
        rand::rng().fill_bytes(&mut encaps_randomness);
        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&mlkem_public, encaps_randomness);

        let ephemeral_secret = EphemeralSecret::random();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let shared_secret_x25519 = ephemeral_secret.diffie_hellman(&x25519_public);

        let mut combined_secret = Vec::with_capacity(SHARED_SECRET_SIZE);
        combined_secret.extend_from_slice(&shared_secret);
        combined_secret.extend_from_slice(shared_secret_x25519.as_bytes());

        let mut salt = [0u8; SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);
        let mut base_nonce = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut base_nonce);

        let aes_key = derive_aes_key(&combined_secret, &salt).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key.data));

        let kem_ct_len = ciphertext.as_slice().len() as u32;
        let mut header = Vec::new();
        header.extend_from_slice(magic);
        header.extend_from_slice(&kem_ct_len.to_be_bytes());
        header.extend_from_slice(ciphertext.as_slice());
        header.extend_from_slice(ephemeral_public.as_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&base_nonce);

        if magic == MAGIC_V2 {
            let prefix_hash: [u8; 32] = Sha256::digest(&header).into();

            let extension_region = encode_tlv_fields(extension_fields);
            header.extend_from_slice(&(extension_region.len() as u32).to_be_bytes());
            header.extend_from_slice(&extension_region);

            let metadata_key = derive_metadata_key(&combined_secret, &salt).unwrap();
            let metadata_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&metadata_key.data));
            let metadata_plaintext = encode_tlv_fields(metadata_fields);
            let metadata_aad = build_metadata_aad(&prefix_hash);
            let metadata_ciphertext = metadata_cipher.encrypt(
                Nonce::from_slice(&base_nonce),
                Payload { msg: metadata_plaintext.as_slice(), aad: &metadata_aad },
            ).unwrap();
            header.extend_from_slice(&(metadata_ciphertext.len() as u32).to_be_bytes());
            header.extend_from_slice(&metadata_ciphertext);
        }

        let header_hash: [u8; 32] = Sha256::digest(&header).into();

        let aad = build_aad(AAD_CHUNK_TYPE_LAST, 0, &header_hash);
        let nonce = get_nonce(&base_nonce, 0).unwrap();
        let body_ciphertext = cipher.encrypt(&nonce, Payload { msg: plaintext, aad: &aad }).unwrap();

        let mut file_bytes = header;
        file_bytes.extend_from_slice(&body_ciphertext);

        (file_bytes, priv_pem)
    }

    // End-to-end tests built on `build_test_pqe_file` -- real crypto, real
    // `decrypt_file` calls, values `encrypt_file` could never itself produce.
    mod pqe2_format_tests {
        use super::*;
        use tempfile::TempDir;

        #[test]
        fn test_decrypt_pqe1_falls_back_to_pqe_suffix_strip() {
            // A PQE1 file has no metadata region to prefer, so an omitted
            // -o must fall back to the pre-existing .pqe-stripping heuristic.
            let dir = TempDir::new().unwrap();
            let (file_bytes, priv_pem) = build_test_pqe_file(MAGIC_V1, &[], &[], b"legacy content");

            let input_path = dir.path().join("legacy.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let result = decrypt_file(input_path.to_str().unwrap(), None, priv_path.to_str().unwrap(), None);
            assert!(result.is_ok(), "{:?}", result.err());

            let expected_output = dir.path().join("legacy");
            assert!(expected_output.exists());
            assert_eq!(fs::read(&expected_output).unwrap(), b"legacy content");
        }

        #[test]
        fn test_decrypt_pqe2_tolerates_unknown_metadata_field() {
            // Simulates a *future* encoder that adds a metadata field this
            // version doesn't know about, interleaved with fields it does.
            let dir = TempDir::new().unwrap();
            let mtime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(1_700_000_000, 0));
            let atime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(1_700_000_001, 0));
            let (file_bytes, priv_pem) = build_test_pqe_file(
                MAGIC_V2,
                &[],
                &[
                    (0xFE, b"unknown-future-field"),
                    (METADATA_FIELD_FILENAME, b"restored.txt"),
                    (METADATA_FIELD_MTIME, &mtime_bytes),
                    (METADATA_FIELD_ATIME, &atime_bytes),
                ],
                b"future content",
            );

            let input_path = dir.path().join("future.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let result = decrypt_file(input_path.to_str().unwrap(), None, priv_path.to_str().unwrap(), None);
            assert!(result.is_ok(), "{:?}", result.err());

            let expected_output = dir.path().join("restored.txt");
            assert!(expected_output.exists());
            assert_eq!(fs::read(&expected_output).unwrap(), b"future content");
        }

        #[test]
        fn test_decrypt_rejects_traversal_in_embedded_filename() {
            // SECURITY: a hostile sender (anyone holding the recipient's
            // public key) embeds a path-traversal filename. Decrypt must
            // never honor it -- it must fall back to .pqe-suffix stripping,
            // and must never write outside the input file's own directory.
            let dir = TempDir::new().unwrap();
            let (file_bytes, priv_pem) = build_test_pqe_file(
                MAGIC_V2,
                &[],
                &[(METADATA_FIELD_FILENAME, b"../../evil")],
                b"malicious sender content",
            );

            let sub_dir = dir.path().join("archive");
            fs::create_dir(&sub_dir).unwrap();
            let input_path = sub_dir.join("backup.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let result = decrypt_file(input_path.to_str().unwrap(), None, priv_path.to_str().unwrap(), None);
            assert!(result.is_ok(), "{:?}", result.err());

            // Falls back to .pqe-suffix stripping, in the SAME directory as the input.
            let expected_output = sub_dir.join("backup");
            assert!(expected_output.exists(), "expected fallback output at {:?}", expected_output);
            assert_eq!(fs::read(&expected_output).unwrap(), b"malicious sender content");

            // The naive traversal target ("../../evil" joined onto the
            // input's directory, i.e. two levels up) must never be created.
            let traversal_target = dir.path().parent().unwrap().join("evil");
            assert!(!traversal_target.exists(),
                    "path traversal target must not exist: {:?}", traversal_target);
        }
    }
