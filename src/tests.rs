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

    /// Shared setup for `build_test_pqe_file`/`build_test_pqe_file_multichunk`:
    /// generates a recipient keypair, does the KEM/DH exchange, and builds
    /// the header (including, for PQE2, the extension and metadata regions).
    /// Returns everything a caller needs to then encrypt a body -- one big
    /// AEAD call, or a real multi-chunk loop -- and compute the final
    /// `header_hash` those chunk AADs must use.
    fn build_test_pqe_header(
        magic: &[u8],
        extension_fields: &[(u8, &[u8])],
        metadata_fields: &[(u8, &[u8])],
    ) -> (Vec<u8>, [u8; 32], [u8; NONCE_SIZE], Aes256Gcm, String) {
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

        (header, header_hash, base_nonce, cipher, priv_pem)
    }

    // Builds a real, cryptographically valid .pqe file plus a matching
    // plain-text private key PEM, entirely from this module's own internals
    // -- bypassing `encrypt_file`. This is what lets the tests below inject
    // header/metadata field values `encrypt_file` itself could never
    // produce (an unrecognized TLV field ID, or a malicious embedded
    // filename containing ".."), which is exactly what's needed to test
    // forward compatibility and the filename sanitizer end-to-end.
    //
    // The body is always a single AEAD call (chunk_index 0, AAD_CHUNK_TYPE_LAST),
    // regardless of plaintext size -- fine for the small payloads these tests
    // use, but NOT a valid stand-in for a real multi-chunk file (decrypt_file
    // would try to split a ciphertext this large into several encrypted_chunk_size
    // reads, each of which would fail AEAD authentication). Use
    // `build_test_pqe_file_multichunk` for anything that needs to exercise
    // real chunk boundaries.
    fn build_test_pqe_file(
        magic: &[u8],
        extension_fields: &[(u8, &[u8])],
        metadata_fields: &[(u8, &[u8])],
        plaintext: &[u8],
    ) -> (Vec<u8>, String) {
        let (header, header_hash, base_nonce, cipher, priv_pem) =
            build_test_pqe_header(magic, extension_fields, metadata_fields);

        let aad = build_aad(AAD_CHUNK_TYPE_LAST, 0, &header_hash);
        let nonce = get_nonce(&base_nonce, 0).unwrap();
        let body_ciphertext = cipher.encrypt(&nonce, Payload { msg: plaintext, aad: &aad }).unwrap();

        let mut file_bytes = header;
        file_bytes.extend_from_slice(&body_ciphertext);

        (file_bytes, priv_pem)
    }

    /// Like `build_test_pqe_file`, but always PQE2 and chunks `plaintext`
    /// exactly as `encrypt_file` does -- CHUNK_SIZE-sized pieces, each its
    /// own AEAD call with the real per-chunk AAD (chunk_type/index/header_hash)
    /// and nonce, only the final piece marked AAD_CHUNK_TYPE_LAST. Needed
    /// because `header_hash` (and therefore every chunk's AAD) depends on
    /// the extension region's exact bytes, so a genuinely old-format
    /// (no-trailer-marker) multi-chunk file can't be produced by stripping
    /// fields out of a real `pqenc encrypt` output after the fact -- that
    /// would change header_hash out from under already-authenticated
    /// chunks and break every tag.
    fn build_test_pqe_file_multichunk(
        extension_fields: &[(u8, &[u8])],
        metadata_fields: &[(u8, &[u8])],
        plaintext: &[u8],
    ) -> (Vec<u8>, String) {
        let (header, header_hash, base_nonce, cipher, priv_pem) =
            build_test_pqe_header(MAGIC_V2, extension_fields, metadata_fields);

        let mut file_bytes = header;
        let chunks: Vec<&[u8]> = if plaintext.is_empty() {
            vec![&[][..]]
        } else {
            plaintext.chunks(CHUNK_SIZE).collect()
        };
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            let is_last = chunk_index + 1 == chunks.len();
            let chunk_type = if is_last { AAD_CHUNK_TYPE_LAST } else { AAD_CHUNK_TYPE_NORMAL };
            let aad = build_aad(chunk_type, chunk_index as u64, &header_hash);
            let nonce = get_nonce(&base_nonce, chunk_index as u64).unwrap();
            let ciphertext = cipher.encrypt(&nonce, Payload { msg: chunk, aad: &aad }).unwrap();
            file_bytes.extend_from_slice(&ciphertext);
        }

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

        #[test]
        fn test_decrypt_pqe2_without_trailer_marker_succeeds() {
            // No EXTENSION_FIELD_CHECKSUM_TRAILER field -- simulates a PQE2
            // file written before the checksum trailer existed. Must decrypt
            // exactly as before: body_end_len's has_trailer=false branch
            // collapses to the raw file length, unchanged from pre-feature
            // behavior. This is the "missing-trailer-on-old-file" backward
            // compatibility case.
            let dir = TempDir::new().unwrap();
            let (file_bytes, priv_pem) = build_test_pqe_file(MAGIC_V2, &[], &[], b"pre-trailer-feature content");

            let input_path = dir.path().join("old.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let output_path = dir.path().join("old_out.bin");
            let result = decrypt_file(
                input_path.to_str().unwrap(), Some(output_path.to_str().unwrap()),
                priv_path.to_str().unwrap(), None,
            );
            assert!(result.is_ok(), "{:?}", result.err());
            assert_eq!(fs::read(&output_path).unwrap(), b"pre-trailer-feature content");
        }

        #[test]
        fn test_decrypt_fails_on_wrong_trailer() {
            // Marker present, but the 32 appended bytes are deliberately
            // wrong. decrypt now runs verify_file as a preflight before
            // touching any key material, so this must fail there -- with a
            // checksum-mismatch error, not a generic decrypt failure -- and
            // never reach the AEAD chunk-decryption pass at all (no output
            // file gets created).
            let dir = TempDir::new().unwrap();
            let (mut file_bytes, priv_pem) = build_test_pqe_file(
                MAGIC_V2,
                &[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])],
                &[],
                b"trailer marker present but wrong",
            );
            file_bytes.extend_from_slice(&[0xABu8; TRAILER_SIZE]);

            let input_path = dir.path().join("wrong_trailer.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let output_path = dir.path().join("wrong_trailer_out.bin");
            let result = decrypt_file(
                input_path.to_str().unwrap(), Some(output_path.to_str().unwrap()),
                priv_path.to_str().unwrap(), None,
            );
            let err = result.expect_err("decrypt should fail the verify preflight on a wrong trailer");
            assert!(format!("{err:#}").contains("CHECKSUM MISMATCH"), "unexpected error: {err:#}");
            assert!(!output_path.exists(), "no output file should be created when verify fails");
        }

        #[test]
        fn test_decrypt_empty_plaintext_with_correct_trailer() {
            // Sharpest instance of the "last chunk shorter than
            // encrypted_chunk_size" landmine: body is exactly TAG_SIZE (16)
            // bytes, so `remaining` is tiny on the very first loop
            // iteration. A correct trailer must not get pulled into that
            // first read.
            use sha2::Digest;
            let dir = TempDir::new().unwrap();
            let (mut file_bytes, priv_pem) = build_test_pqe_file(
                MAGIC_V2,
                &[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])],
                &[],
                b"",
            );
            let trailer: [u8; TRAILER_SIZE] = Sha256::digest(&file_bytes).into();
            file_bytes.extend_from_slice(&trailer);

            let input_path = dir.path().join("empty_with_trailer.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let output_path = dir.path().join("empty_with_trailer_out.bin");
            let result = decrypt_file(
                input_path.to_str().unwrap(), Some(output_path.to_str().unwrap()),
                priv_path.to_str().unwrap(), None,
            );
            assert!(result.is_ok(), "{:?}", result.err());
            assert_eq!(fs::read(&output_path).unwrap(), b"");
        }

        #[test]
        fn test_decrypt_multichunk_without_trailer_marker_backward_compat() {
            // A genuinely old-format PQE2 file at multi-chunk scale: no
            // EXTENSION_FIELD_CHECKSUM_TRAILER, several real per-chunk AEAD
            // calls (not one big blob), last chunk not aligned to a chunk
            // boundary. Can't be built by editing real `pqenc encrypt`
            // output after the fact (see build_test_pqe_file_multichunk's
            // doc comment for why), so this uses the from-scratch
            // multi-chunk builder instead.
            let dir = TempDir::new().unwrap();
            let plaintext = vec![0x5Au8; (2 * CHUNK_SIZE) + 12_345]; // 2 full chunks + a short final chunk
            let (file_bytes, priv_pem) = build_test_pqe_file_multichunk(&[], &[], &plaintext);

            let input_path = dir.path().join("old_multichunk.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let output_path = dir.path().join("old_multichunk_out.bin");
            let result = decrypt_file(
                input_path.to_str().unwrap(), Some(output_path.to_str().unwrap()),
                priv_path.to_str().unwrap(), None,
            );
            assert!(result.is_ok(), "{:?}", result.err());
            assert_eq!(fs::read(&output_path).unwrap(), plaintext);
        }

        #[test]
        fn test_decrypt_multichunk_with_correct_trailer() {
            // Multi-chunk companion to test_decrypt_empty_plaintext_with_correct_trailer:
            // several real chunks, a non-boundary-aligned final chunk, marker
            // present, and a correctly-computed trailer appended.
            use sha2::Digest;
            let dir = TempDir::new().unwrap();
            let plaintext = vec![0xA5u8; (3 * CHUNK_SIZE) + 777];
            let (mut file_bytes, priv_pem) = build_test_pqe_file_multichunk(
                &[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])],
                &[],
                &plaintext,
            );
            let trailer: [u8; TRAILER_SIZE] = Sha256::digest(&file_bytes).into();
            file_bytes.extend_from_slice(&trailer);

            let input_path = dir.path().join("multichunk_with_trailer.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let output_path = dir.path().join("multichunk_with_trailer_out.bin");
            let result = decrypt_file(
                input_path.to_str().unwrap(), Some(output_path.to_str().unwrap()),
                priv_path.to_str().unwrap(), None,
            );
            assert!(result.is_ok(), "{:?}", result.err());
            assert_eq!(fs::read(&output_path).unwrap(), plaintext);
        }

        #[test]
        fn test_verify_open_file_leaves_handle_reusable_for_decrypt() {
            // decrypt_file no longer verifies one handle and reopens the path
            // for a second one -- it reuses the exact handle verify_open_file
            // was given, seeking back to the start of the body (see
            // verify_open_file's doc comment). This proves that reuse works:
            // after verifying, the same handle can be seeked and read to
            // recover exactly the body bytes decrypt_file's AEAD loop needs,
            // with no second `File::open` on the path involved.
            //
            // The path is also deleted between opening and verifying: on
            // Unix, an open file descriptor keeps referencing the original
            // inode after unlink, so this only passes if verify_open_file
            // truly operates on the handle it was given rather than
            // (re)opening the path itself -- directly demonstrating decrypt's
            // fix is bound to file identity, not to the path, closing the
            // verify/decrypt race the fix addresses.
            use sha2::Digest;
            let dir = TempDir::new().unwrap();
            let plaintext = vec![0x42u8; (2 * CHUNK_SIZE) + 999];
            let (mut file_bytes, _priv_pem) = build_test_pqe_file_multichunk(
                &[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])],
                &[],
                &plaintext,
            );
            let trailer: [u8; TRAILER_SIZE] = Sha256::digest(&file_bytes).into();
            file_bytes.extend_from_slice(&trailer);

            let input_path = dir.path().join("reuse.pqe");
            fs::write(&input_path, &file_bytes).unwrap();

            let mut fin = File::open(&input_path).unwrap();
            #[cfg(unix)]
            fs::remove_file(&input_path).unwrap();

            let verified = verify_open_file(&mut fin, input_path.to_str().unwrap())
                .expect("verify should succeed against the already-open handle");

            let header_end_pos = verified.parsed.header_bytes.len() as u64;
            let body_len = (verified.body_end - header_end_pos) as usize;

            fin.seek(SeekFrom::Start(header_end_pos))
                .expect("the verified handle must still be seekable");
            let mut body = vec![0u8; body_len];
            fin.read_exact(&mut body)
                .expect("body must be readable on the same handle after verification, with no reopen");

            let expected_body = &file_bytes[header_end_pos as usize..verified.body_end as usize];
            assert_eq!(body, expected_body, "reused handle must read back the exact verified body bytes");
        }
    }

    // Regression tests for TODO.md #1: claim_output_and_temp must not arm a
    // TempFileGuard on the temp path until create_new_exclusive on that exact
    // path has succeeded -- arming it earlier lets TempFileGuard::Drop delete
    // a file this process never created if that random path happens to
    // collide with something already there (attacker-planted or otherwise).
    mod claim_output_and_temp_tests {
        use super::*;
        use tempfile::TempDir;

        #[test]
        fn test_claim_output_and_temp_does_not_create_temp_file() {
            let dir = TempDir::new().unwrap();
            let output_path = dir.path().join("output.enc");

            let (output_guard, temp_path) = claim_output_and_temp(
                output_path.to_str().unwrap(),
                "test claim context",
            ).unwrap();

            assert!(!std::path::Path::new(&temp_path).exists(),
                "claim_output_and_temp must not create the temp file itself");
            assert!(output_path.exists(), "output path must be claimed immediately");
            drop(output_guard);
        }

        #[test]
        fn test_claim_output_and_temp_temp_collision_leaves_sentinel_unchanged() {
            // Simulates an attacker (or unrelated process) planting a file at
            // the exact random temp path claim_output_and_temp generated,
            // before this process gets to claim it.
            let dir = TempDir::new().unwrap();
            let output_path = dir.path().join("output.enc");

            let (output_guard, temp_path) = claim_output_and_temp(
                output_path.to_str().unwrap(),
                "test claim context",
            ).unwrap();

            const SENTINEL: &[u8] = b"pre-existing file that this process does not own";
            fs::write(&temp_path, SENTINEL).unwrap();

            // Mirror exactly what every real caller does immediately after
            // claim_output_and_temp.
            let create_result = create_new_exclusive(&temp_path, OWNER_ONLY_MODE);
            assert!(create_result.is_err(), "create_new_exclusive must fail: the path is already occupied");
            assert_eq!(create_result.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);

            // The fix: temp_path is a plain String here, not an armed guard,
            // so nothing gets dropped/unlinked as a result of the failed
            // create above. create_new never truncates, so the sentinel's
            // original bytes must survive intact.
            assert_eq!(fs::read(&temp_path).unwrap(), SENTINEL,
                "pre-existing file at the colliding temp path must not be modified or deleted");

            // output_guard's own claim is a separate, correctly-owned file --
            // confirm the fix didn't disturb it.
            assert!(output_path.exists());
            drop(output_guard);
            assert!(!output_path.exists(), "output_guard still cleans up its own file normally");
        }
    }
