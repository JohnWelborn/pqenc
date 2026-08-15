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
        for line in &lines[1..lines.len() - 1] {
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

        let key1 = derive_key_from_passphrase(passphrase, &salt, &Argon2Params::CURRENT).unwrap();
        let key2 = derive_key_from_passphrase(passphrase, &salt, &Argon2Params::CURRENT).unwrap();

        assert_eq!(key1.data, key2.data);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let passphrase = b"test-passphrase";
        let salt1 = [1u8; ARGON2_SALT_SIZE];
        let salt2 = [2u8; ARGON2_SALT_SIZE];

        let key1 = derive_key_from_passphrase(passphrase, &salt1, &Argon2Params::CURRENT).unwrap();
        let key2 = derive_key_from_passphrase(passphrase, &salt2, &Argon2Params::CURRENT).unwrap();

        assert_ne!(key1.data, key2.data);
    }

    #[test]
    fn test_derive_key_empty_passphrase() {
        let salt = [0u8; ARGON2_SALT_SIZE];
        let result = derive_key_from_passphrase(b"", &salt, &Argon2Params::CURRENT);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_output_length() {
        let passphrase = b"passphrase";
        let salt = [0u8; ARGON2_SALT_SIZE];
        let key = derive_key_from_passphrase(passphrase, &salt, &Argon2Params::CURRENT).unwrap();
        assert_eq!(key.data.len(), ARGON2_KEY_LENGTH);
    }
}

// Private key encryption/decryption tests. encrypt_private_key always
// writes the V1 envelope format, so these exercise it end-to-end; see
// key_envelope_format_tests below for V1-structural coverage.
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

        let (parsed_mlkem, parsed_x25519) = parse_public_composite_key(&composite).unwrap();

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

        let (parsed_mlkem, parsed_x25519) = parse_private_composite_key(&composite).unwrap();

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

/// Builds a synthetic V1 envelope with caller-chosen Argon2 params, so
/// tests can prove `decrypt_private_key` actually uses the params
/// *recorded in the envelope* rather than always falling back to
/// `Argon2Params::CURRENT`. Mirrors `encrypt_private_key`'s own envelope
/// assembly exactly.
fn build_v1_key_envelope(
    passphrase: &[u8],
    composite_key: &[u8],
    params: &Argon2Params,
) -> Vec<u8> {
    use rand::RngExt;

    let salt: [u8; ARGON2_SALT_SIZE] = rand::rng().random();
    let key = derive_key_from_passphrase(passphrase, &salt, params).unwrap();
    let nonce: [u8; PBE_NONCE_SIZE] = rand::rng().random();
    let cipher = Aes256Gcm::new(aes_key_from_slice(&key.data));

    let mut header = Vec::new();
    header.push(KEY_ENVELOPE_VERSION_V1);
    header.push(KDF_ALG_ARGON2ID);
    header.push(AEAD_ALG_AES_256_GCM);
    let kdf_params = encode_kdf_params(params);
    header.extend_from_slice(&(kdf_params.len() as u32).to_be_bytes());
    header.extend_from_slice(&kdf_params);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let mut aad = Vec::new();
    aad.extend_from_slice(KEY_ENVELOPE_AAD_V1_PREFIX);
    aad.extend_from_slice(&header);

    let ciphertext = cipher
        .encrypt(
            aes_nonce_from_slice(&nonce),
            Payload {
                msg: composite_key,
                aad: &aad,
            },
        )
        .unwrap();

    let mut result = header;
    result.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    result.extend_from_slice(&ciphertext);
    result
}

/// Builds a structurally well-formed V1 envelope header (with the given,
/// possibly-invalid, claimed params) plus an all-zero fake ciphertext of
/// the right length -- without ever calling Argon2/AES-GCM. Needed for
/// tests of params so out-of-range (huge memory cost, wrong key length)
/// that actually deriving/encrypting under them would hang or panic; since
/// decrypt_private_key must reject these during parameter validation,
/// before ever deriving a key or touching AEAD, the ciphertext bytes'
/// authenticity is irrelevant to what's being tested.
fn build_v1_envelope_with_fake_ciphertext(params: &Argon2Params, plaintext_len: usize) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(KEY_ENVELOPE_VERSION_V1);
    header.push(KDF_ALG_ARGON2ID);
    header.push(AEAD_ALG_AES_256_GCM);
    let kdf_params = encode_kdf_params(params);
    header.extend_from_slice(&(kdf_params.len() as u32).to_be_bytes());
    header.extend_from_slice(&kdf_params);
    header.extend_from_slice(&[0u8; ARGON2_SALT_SIZE]);
    header.extend_from_slice(&[0u8; PBE_NONCE_SIZE]);

    let mut envelope = header;
    let fake_ciphertext = vec![0u8; plaintext_len + TAG_SIZE];
    envelope.extend_from_slice(&(fake_ciphertext.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&fake_ciphertext);
    envelope
}

// V1 private-key envelope structural-corruption tests. key_encryption_tests
// above only ever exercises real encrypt_private_key output with default
// params; these use build_v1_key_envelope/build_v1_envelope_with_fake_ciphertext
// to construct byte shapes with caller-chosen or deliberately-invalid
// fields, mirroring the pqe3_format_tests precedent below for the main .pqe
// file format.
mod key_envelope_format_tests {
    use super::*;

    // The core property this envelope format establishes: parameters
    // *recorded in the envelope*, not hard-coded current defaults, drive
    // key derivation -- so a future ARGON2_* hardening bump can't affect
    // keys written under different recorded parameters.
    #[test]
    fn test_decrypt_v1_roundtrip_with_nondefault_params() {
        let composite_key = vec![0xCDu8; COMPOSITE_PRIVATE_KEY_SIZE];
        let params = Argon2Params {
            memory_cost: 32768,
            time_cost: 2,
            parallelism: 1,
            key_length: 32,
        };
        let envelope = build_v1_key_envelope(b"passphrase", &composite_key, &params);

        let decrypted = decrypt_private_key(&envelope, b"passphrase").unwrap();
        assert_eq!(decrypted.data, composite_key);
    }

    #[test]
    fn test_decrypt_v1_unrecognized_version_byte() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        envelope[0] = 0x02;

        match decrypt_private_key(&envelope, b"passphrase") {
            Err(e) => assert!(e.to_string().contains("version")),
            Ok(_) => panic!("expected an error for an unrecognized envelope version"),
        }
    }

    #[test]
    fn test_decrypt_v1_unrecognized_kdf_algorithm_id() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        envelope[1] = 0xFF;

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_v1_unrecognized_aead_algorithm_id() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        envelope[2] = 0xFF;

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    // Regression test for the Key::<Aes256Gcm>::from_slice panic risk: an
    // envelope claiming a key_length other than AES_KEY_SIZE must fail
    // gracefully, not panic.
    #[test]
    fn test_decrypt_v1_rejects_mismatched_key_length() {
        let bad_params = Argon2Params {
            memory_cost: ARGON2_MEMORY_COST,
            time_cost: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            key_length: 16,
        };
        let envelope =
            build_v1_envelope_with_fake_ciphertext(&bad_params, COMPOSITE_PRIVATE_KEY_SIZE);

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_v1_rejects_oversized_argon2_memory_cost() {
        let bad_params = Argon2Params {
            memory_cost: MAX_ENVELOPE_ARGON2_MEMORY_COST + 1,
            time_cost: 1,
            parallelism: 1,
            key_length: 32,
        };
        let envelope =
            build_v1_envelope_with_fake_ciphertext(&bad_params, COMPOSITE_PRIVATE_KEY_SIZE);

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_v1_rejects_oversized_kdf_params_length_claim() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        // kdf_params_len is the 4 bytes right after the 3 fixed header
        // bytes; inflate it far past what actually follows.
        envelope[3..7].copy_from_slice(&(u32::MAX).to_be_bytes());

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_v1_truncated_at_every_offset() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let envelope = build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);

        for len in 0..envelope.len() {
            let truncated = &envelope[..len];
            let result = decrypt_private_key(truncated, b"passphrase");
            assert!(result.is_err(), "truncation at {} did not fail", len);
        }
    }

    #[test]
    fn test_decrypt_v1_trailing_garbage_rejected() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        envelope.push(0x00);

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_v1_tampered_header_byte_fails() {
        let composite_key = vec![0x11u8; COMPOSITE_PRIVATE_KEY_SIZE];
        let mut envelope =
            build_v1_key_envelope(b"passphrase", &composite_key, &Argon2Params::CURRENT);
        // Byte 10 falls inside the KDF-params TLV region (which starts at
        // byte 7, right after the 3 fixed bytes + 4-byte length prefix),
        // well past the algorithm-id bytes already covered by the tests
        // above -- proves the AAD covers the whole header, not just its
        // first few bytes.
        envelope[10] ^= 0xFF;

        let result = decrypt_private_key(&envelope, b"passphrase");
        assert!(result.is_err());
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
            assert_eq!(
                line.chars().count(),
                19,
                "every line is 19 chars wide: {}",
                line
            );
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
        mlkem_sk
            [MLKEM1024_PUBLIC_KEY_OFFSET..MLKEM1024_PUBLIC_KEY_OFFSET + MLKEM1024_PUBLIC_KEY_SIZE]
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

// Pure unit tests for the TLV/metadata/output-resolution helpers -- no
// crypto or file I/O involved.
mod metadata_tests {
    use super::*;
    use tempfile::TempDir;

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
        let encoded = encode_tlv_fields(&[(0xFE, b"future"), (0x01, b"known")]);
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
        assert_eq!(
            decoded.mtime,
            Some(filetime::FileTime::from_unix_time(100, 0))
        );
        assert_eq!(
            decoded.atime,
            Some(filetime::FileTime::from_unix_time(200, 0))
        );
    }

    #[test]
    fn test_encode_metadata_plaintext_none_is_empty() {
        assert!(encode_metadata_plaintext(None).is_empty());
    }

    #[test]
    fn test_metadata_tlv_size_scales_with_filename_length() {
        // encrypt_file_with_segment_size bails if encode_metadata_plaintext's
        // output exceeds MAX_METADATA_TLV_SIZE_V4, so the metadata TLV
        // always fits entirely inside PQE4 chunk 0. Exercising that bail
        // via a real file isn't practical -- OS filename limits (typically
        // 255 bytes) are far below the cap -- so this proves the arithmetic
        // the bail depends on instead: a filename long enough to push the
        // TLV over the cap really does, and a realistic one doesn't.
        let mtime = filetime::FileTime::from_unix_time(0, 0);
        let atime = filetime::FileTime::from_unix_time(0, 0);

        let realistic = SourceMetadata {
            filename: Some("a".repeat(200)),
            mtime,
            atime,
        };
        assert!(encode_metadata_plaintext(Some(&realistic)).len() <= MAX_METADATA_TLV_SIZE_V4);

        let oversized = SourceMetadata {
            filename: Some("a".repeat(MAX_METADATA_TLV_SIZE_V4 + 100)),
            mtime,
            atime,
        };
        assert!(encode_metadata_plaintext(Some(&oversized)).len() > MAX_METADATA_TLV_SIZE_V4);
    }

    #[test]
    fn test_sanitize_rejects_traversal_and_separators() {
        for bad in [
            "..",
            ".",
            "",
            "../evil",
            "../../evil",
            "/etc/passwd",
            "a/b",
            "a\\b",
            "..\\evil",
            "a\0b",
        ] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_accepts_ordinary_filenames() {
        for good in ["report.pdf", "my archive.tar.gz", "IMG_0001.JPG", ".hidden"] {
            assert_eq!(sanitize_embedded_filename(good).as_deref(), Some(good));
        }
    }

    // The colon in a timestamp-style name is ordinary and must be accepted
    // on Unix, but is Windows-reserved (see `filename_unsafe_on_windows`) --
    // kept platform-specific rather than in the shared accept list above,
    // which windows-latest CI also executes.
    #[test]
    #[cfg(not(windows))]
    fn test_sanitize_accepts_colon_in_timestamp_name_on_unix() {
        assert_eq!(
            sanitize_embedded_filename("2024-01-01T12:00:00.txt").as_deref(),
            Some("2024-01-01T12:00:00.txt")
        );
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
        assert_eq!(
            resolve_encrypt_output("in.txt", None).unwrap(),
            "in.txt.pqe"
        );
    }

    #[test]
    fn test_resolve_encrypt_output_rejects_stdin_without_explicit_output() {
        assert!(resolve_encrypt_output("-", None).is_err());
        assert!(resolve_encrypt_output("/dev/stdin", None).is_err());
    }

    #[test]
    fn test_resolve_encrypt_output_defaults_directory_to_tar_gz_pqe_suffix() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("mydir");
        fs::create_dir(&sub).unwrap();
        assert_eq!(
            resolve_encrypt_output(sub.to_str().unwrap(), None).unwrap(),
            format!("{}.tar.gz.pqe", sub.to_str().unwrap())
        );
    }

    #[test]
    fn test_resolve_encrypt_output_directory_trailing_slash_matches_without() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("mydir");
        fs::create_dir(&sub).unwrap();
        let with_slash = format!("{}/", sub.to_str().unwrap());
        assert_eq!(
            resolve_encrypt_output(&with_slash, None).unwrap(),
            format!("{}.tar.gz.pqe", sub.to_str().unwrap())
        );
    }

    #[test]
    fn test_resolve_encrypt_output_directory_input_still_honors_explicit_output() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("mydir");
        fs::create_dir(&sub).unwrap();
        assert_eq!(
            resolve_encrypt_output(sub.to_str().unwrap(), Some("explicit.pqe".to_string()))
                .unwrap(),
            "explicit.pqe"
        );
    }

    #[test]
    fn test_resolve_encrypt_output_dot_is_ok_and_not_self_contained() {
        // The test binary's ambient cwd isn't stable/meaningful enough to
        // pin an exact string against (same reasoning as
        // test_directory_basename_resolves_dot_and_dotdot_via_canonicalize
        // below), but the default output for "." must land beside cwd, not
        // inside it -- that's exactly the bug this guards against.
        let resolved = resolve_encrypt_output(".", None).unwrap();
        let resolved_path = std::path::Path::new(&resolved);
        assert!(resolved_path.is_absolute());
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(resolved_path.parent(), cwd.parent());
    }

    #[test]
    fn test_resolve_encrypt_output_trailing_dotdot_resolves_to_sibling_of_parent() {
        let dir = TempDir::new().unwrap();
        let child = dir.path().join("child");
        fs::create_dir(&child).unwrap();

        // "<child>/.." canonicalizes to `dir`; the default output must be a
        // sibling of `dir`, never a path inside `child` (which is what
        // naively suffixing the typed string used to produce).
        let trailing_dotdot = child.join("..");
        let resolved = resolve_encrypt_output(trailing_dotdot.to_str().unwrap(), None).unwrap();
        let expected = format!(
            "{}.tar.gz.pqe",
            dir.path().canonicalize().unwrap().to_str().unwrap()
        );
        assert_eq!(resolved, expected);
        assert!(!resolved.starts_with(child.to_str().unwrap()));
    }

    #[test]
    fn test_resolve_encrypt_output_root_directory_fails_with_accurate_message() {
        let err = resolve_encrypt_output("/", None).unwrap_err().to_string();
        assert!(
            err.contains("filesystem root"),
            "unexpected message: {err}"
        );
        assert!(err.contains("--output"), "should suggest --output: {err}");
    }

    #[test]
    fn test_directory_basename_extracts_final_component() {
        assert_eq!(directory_basename("mydir").unwrap(), "mydir");
        assert_eq!(directory_basename("mydir/").unwrap(), "mydir");
        assert_eq!(directory_basename("path/to/mydir").unwrap(), "mydir");
        assert_eq!(directory_basename("path/to/mydir/").unwrap(), "mydir");
    }

    #[test]
    fn test_directory_basename_resolves_dot_and_dotdot_via_canonicalize() {
        // Path::file_name() returns None for these, but they name a real,
        // nameable directory once canonicalized -- unlike the test runner's
        // cwd (whose name isn't worth pinning here), a TempDir gives a
        // known, controlled parent/child pair to assert against.
        assert!(directory_basename(".").is_ok());
        assert!(directory_basename("..").is_ok());

        let dir = TempDir::new().unwrap();
        let parent_name = dir.path().file_name().unwrap().to_str().unwrap();
        let child = dir.path().join("child");
        fs::create_dir(&child).unwrap();

        // "<child>/.." also has no raw file_name() (ends in ".."), and
        // canonicalizes to the same parent directory.
        let trailing_dotdot = child.join("..");
        assert_eq!(
            directory_basename(trailing_dotdot.to_str().unwrap()).unwrap(),
            parent_name
        );
    }

    #[test]
    fn test_directory_basename_rejects_root_and_empty_with_accurate_message() {
        let root_err = directory_basename("/").unwrap_err().to_string();
        assert!(
            root_err.contains("filesystem root"),
            "unexpected message: {root_err}"
        );
        assert!(!root_err.contains("pass an explicit --output"));

        let empty_err = directory_basename("").unwrap_err().to_string();
        assert!(
            !empty_err.contains("pass an explicit --output"),
            "unexpected message: {empty_err}"
        );
    }

    #[test]
    fn test_resolve_decrypt_output_prefers_sanitized_embedded_filename() {
        let resolved =
            resolve_decrypt_output("/tmp/archive/backup.pqe", Some("report.pdf")).unwrap();
        // Built via Path::join, not a hardcoded "/"-joined literal: the
        // parent directory retains its original separators (from the input
        // string) while the joined filename uses the platform's native
        // separator, so the two can differ within a single path on Windows.
        let expected = std::path::Path::new("/tmp/archive")
            .join("report.pdf")
            .to_string_lossy()
            .into_owned();
        assert_eq!(resolved, expected);
    }

    #[test]
    fn test_resolve_decrypt_output_falls_back_when_embedded_name_unsafe() {
        let resolved = resolve_decrypt_output("/tmp/backup.pqe", Some("../../evil")).unwrap();
        assert_eq!(resolved, "/tmp/backup");
        assert!(!resolved.contains(".."));
    }

    #[test]
    fn test_resolve_decrypt_output_strips_pqe_suffix_without_metadata() {
        assert_eq!(
            resolve_decrypt_output("/tmp/x.pqe", None).unwrap(),
            "/tmp/x"
        );
    }

    #[test]
    fn test_resolve_decrypt_output_requires_explicit_output_without_suffix_or_metadata() {
        assert!(resolve_decrypt_output("/tmp/x.bin", None).is_err());
    }
}

/// Builds a real, cryptographically valid PQE3 file plus a matching
/// plain-text private key PEM, entirely from this module's own internals
/// -- bypassing `encrypt_file`. This is what lets tests inject metadata
/// field values `encrypt_file` itself could never produce (a malicious
/// embedded filename containing ".."), and control whether the checksum
/// trailer marker/trailer bytes are present at all (`encrypt_file` always
/// includes both).
///
/// The body is chunked exactly as `encrypt_file` does -- CHUNK_SIZE-sized
/// pieces, each its own AEAD call with the real per-chunk AAD
/// (version/chunk_type/segment_index/local_chunk_index/header_hash) and
/// nonce, only the final piece marked AAD_CHUNK_TYPE_LAST. All chunks use
/// segment 0 (`derive_body_key_v3` with `segment_index = 0`) -- fine for
/// the small-to-moderate payloads these tests use; multi-segment behavior
/// has its own dedicated coverage in `pqe3_format_tests` below.
fn build_test_pqe3_file(
    metadata_fields: &[(u8, &[u8])],
    plaintext: &[u8],
    include_trailer: bool,
) -> (Vec<u8>, String) {
    use sha2::Digest;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

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

    let kem_ct_len = ciphertext.as_slice().len() as u32;
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC_V3);
    header.extend_from_slice(&kem_ct_len.to_be_bytes());
    header.extend_from_slice(ciphertext.as_slice());
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    let prefix_hash: [u8; 32] = Sha256::digest(&header).into();

    let extension_region = if include_trailer {
        encode_tlv_fields(&[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])])
    } else {
        encode_tlv_fields(&[])
    };
    header.extend_from_slice(&(extension_region.len() as u32).to_be_bytes());
    header.extend_from_slice(&extension_region);

    let metadata_key = derive_metadata_key(&combined_secret, &salt).unwrap();
    let metadata_cipher = Aes256Gcm::new(aes_key_from_slice(&metadata_key.data));
    let metadata_plaintext = encode_tlv_fields(metadata_fields);
    let metadata_aad = build_metadata_aad(&prefix_hash);
    let metadata_ciphertext = metadata_cipher
        .encrypt(
            aes_nonce_from_slice(&base_nonce),
            Payload {
                msg: metadata_plaintext.as_slice(),
                aad: &metadata_aad,
            },
        )
        .unwrap();
    header.extend_from_slice(&(metadata_ciphertext.len() as u32).to_be_bytes());
    header.extend_from_slice(&metadata_ciphertext);

    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    let body_key = derive_body_key_v3(&combined_secret, &salt, 0).unwrap();
    let cipher = Aes256Gcm::new(aes_key_from_slice(&body_key.data));

    let mut file_bytes = header;
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(CHUNK_SIZE).collect()
    };
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_index + 1 == chunks.len();
        let chunk_type = if is_last {
            AAD_CHUNK_TYPE_LAST
        } else {
            AAD_CHUNK_TYPE_NORMAL
        };
        let aad = build_aad_v3(chunk_type, 0, chunk_index as u64, &header_hash);
        let nonce = get_nonce(&base_nonce, chunk_index as u64).unwrap();
        let chunk_ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .unwrap();
        file_bytes.extend_from_slice(&chunk_ciphertext);
    }

    if include_trailer {
        let trailer: [u8; TRAILER_SIZE] = Sha256::digest(&file_bytes).into();
        file_bytes.extend_from_slice(&trailer);
    }

    (file_bytes, priv_pem)
}

/// Builds a real, cryptographically valid PQE4 file plus a matching
/// plain-text private key PEM, entirely from this module's own internals --
/// bypassing `encrypt_file`. Mirrors `build_test_pqe3_file` above: same
/// recipient keypair/DH/header-prefix setup, but the header ends after the
/// extension region (no metadata-region fields), and `metadata_fields` --
/// instead of being AEAD-encrypted separately -- is TLV-encoded,
/// length-prefixed, and prepended to `plaintext` before chunking, exactly as
/// `encrypt_file_with_segment_size` now does.
fn build_test_pqe4_file(
    metadata_fields: &[(u8, &[u8])],
    plaintext: &[u8],
    include_trailer: bool,
) -> (Vec<u8>, String) {
    use sha2::Digest;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

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

    let kem_ct_len = ciphertext.as_slice().len() as u32;
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC_V4);
    header.extend_from_slice(&kem_ct_len.to_be_bytes());
    header.extend_from_slice(ciphertext.as_slice());
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);

    let extension_region = if include_trailer {
        encode_tlv_fields(&[(EXTENSION_FIELD_CHECKSUM_TRAILER, &[])])
    } else {
        encode_tlv_fields(&[])
    };
    header.extend_from_slice(&(extension_region.len() as u32).to_be_bytes());
    header.extend_from_slice(&extension_region);

    // No metadata region: the header ends here for PQE4.
    let header_hash: [u8; 32] = Sha256::digest(&header).into();

    // Metadata TLV, length-prefixed and prepended to the real plaintext --
    // this is what makes it the start of chunk 0 once chunked below.
    let metadata_tlv = encode_tlv_fields(metadata_fields);
    let mut full_plaintext = Vec::with_capacity(4 + metadata_tlv.len() + plaintext.len());
    full_plaintext.extend_from_slice(&(metadata_tlv.len() as u32).to_be_bytes());
    full_plaintext.extend_from_slice(&metadata_tlv);
    full_plaintext.extend_from_slice(plaintext);

    let body_key = derive_body_key_v3(&combined_secret, &salt, 0).unwrap();
    let cipher = Aes256Gcm::new(aes_key_from_slice(&body_key.data));

    let mut file_bytes = header;
    // full_plaintext is never empty (always >= 4 bytes for the length
    // prefix), unlike build_test_pqe3_file's plaintext, so there's no need
    // for its empty-plaintext special case here.
    let chunks: Vec<&[u8]> = full_plaintext.chunks(CHUNK_SIZE).collect();
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_index + 1 == chunks.len();
        let chunk_type = if is_last {
            AAD_CHUNK_TYPE_LAST
        } else {
            AAD_CHUNK_TYPE_NORMAL
        };
        let aad = build_aad(AAD_VERSION_V4, chunk_type, 0, chunk_index as u64, &header_hash);
        let nonce = get_nonce(&base_nonce, chunk_index as u64).unwrap();
        let chunk_ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .unwrap();
        file_bytes.extend_from_slice(&chunk_ciphertext);
    }

    if include_trailer {
        let trailer: [u8; TRAILER_SIZE] = Sha256::digest(&file_bytes).into();
        file_bytes.extend_from_slice(&trailer);
    }

    (file_bytes, priv_pem)
}

// Regression tests: claim_output_and_temp must not arm a TempFileGuard on
// the temp path until create_new_exclusive on that exact path has
// succeeded -- arming it earlier lets TempFileGuard::Drop delete a file
// this process never created if that random path happens to collide with
// something already there (attacker-planted or otherwise).
mod claim_output_and_temp_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_claim_output_and_temp_does_not_create_temp_file() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");

        let claim =
            claim_output_and_temp(output_path.to_str().unwrap(), "test claim context").unwrap();

        assert!(
            !std::path::Path::new(&claim.temp_path).exists(),
            "claim_output_and_temp must not create the temp file itself"
        );
        assert!(
            output_path.exists(),
            "output path must be claimed immediately"
        );
        drop(claim);
    }

    #[test]
    fn test_claim_output_and_temp_temp_collision_leaves_sentinel_unchanged() {
        // Simulates an attacker (or unrelated process) planting a file at
        // the exact random temp path claim_output_and_temp generated,
        // before this process gets to claim it.
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");

        let claim =
            claim_output_and_temp(output_path.to_str().unwrap(), "test claim context").unwrap();

        const SENTINEL: &[u8] = b"pre-existing file that this process does not own";
        fs::write(&claim.temp_path, SENTINEL).unwrap();

        // Mirror exactly what every real caller does immediately after
        // claim_output_and_temp.
        let create_result = create_new_exclusive(&claim.temp_path, OWNER_ONLY_MODE);
        assert!(
            create_result.is_err(),
            "create_new_exclusive must fail: the path is already occupied"
        );
        assert_eq!(
            create_result.unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );

        // The fix: temp_path is a plain String here, not an armed guard,
        // so nothing gets dropped/unlinked as a result of the failed
        // create above. create_new never truncates, so the sentinel's
        // original bytes must survive intact.
        assert_eq!(
            fs::read(&claim.temp_path).unwrap(),
            SENTINEL,
            "pre-existing file at the colliding temp path must not be modified or deleted"
        );

        // output_guard's own claim is a separate, correctly-owned file --
        // confirm the fix didn't disturb it.
        assert!(output_path.exists());
        drop(claim);
        assert!(
            !output_path.exists(),
            "output_guard still cleans up its own file normally"
        );
    }
}

// Regression tests for reservation-placeholder reclaim: a placeholder left
// behind by a process that was SIGKILLed or lost power before it could
// clean up (TempFileGuard::Drop cannot run in either case) must be
// recognized as pqenc's own orphaned reservation and safely reclaimed on
// the next attempt -- but only once this process holds the sibling
// `<output>.lock` exclusively, since that's what proves no cooperating
// pqenc process can still own it. Liveness is determined solely by whether
// that lock is held; elapsed time is never consulted.
mod reservation_reclaim_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_orphaned_placeholder_is_reclaimed_regardless_of_age() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");

        fs::write(&output_path, RESERVATION_MARKER).unwrap();
        // Deliberately not backdated -- mtime is "now". Age is no longer
        // consulted at all: reclaim must succeed as soon as nothing holds
        // the sibling lock, regardless of how fresh the placeholder looks.

        let claim = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context")
            .expect("an orphaned placeholder must be reclaimed regardless of its age");

        assert_eq!(
            fs::read(&output_path).unwrap(),
            RESERVATION_MARKER,
            "claim must leave a fresh reservation placeholder in place"
        );
        drop(claim);
        assert!(
            !output_path.exists(),
            "guard still cleans up the reclaimed placeholder normally"
        );
    }

    #[test]
    fn test_placeholder_is_not_reclaimed_while_a_competitor_holds_the_lock() {
        // Simulates a genuinely concurrent, still-running pqenc process by
        // acquiring the sibling lock directly, the same way a real
        // competitor's claim_output_and_temp call would. This is the
        // previously-missing coverage: earlier tests only ever simulated
        // liveness via a fresh mtime, never an actually-held lock.
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");
        fs::write(&output_path, RESERVATION_MARKER).unwrap();

        let competitor_lock = acquire_output_lock(output_path.to_str().unwrap())
            .expect("test setup: competitor must be able to take the lock first");

        let result = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context");
        assert!(
            result.is_err(),
            "a placeholder guarded by a live competitor's lock must not be reclaimed"
        );
        assert_eq!(
            fs::read(&output_path).unwrap(),
            RESERVATION_MARKER,
            "the live competitor's placeholder must survive a failed claim attempt untouched"
        );

        drop(competitor_lock);
        let claim = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context")
            .expect("once the competitor's lock is released, the same placeholder is reclaimable");
        drop(claim);
    }

    #[test]
    fn test_unrelated_content_same_length_is_not_reclaimed() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");

        let sentinel = vec![b'X'; RESERVATION_MARKER.len()];
        fs::write(&output_path, &sentinel).unwrap();

        let result = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context");
        assert!(result.is_err(), "unrelated content must never be reclaimed");
        assert_eq!(
            fs::read(&output_path).unwrap(),
            sentinel,
            "unrelated file must survive a failed claim attempt byte-for-byte"
        );
    }

    #[test]
    fn test_unrelated_content_different_length_is_not_reclaimed() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");

        const SENTINEL: &[u8] = b"short";
        fs::write(&output_path, SENTINEL).unwrap();

        let result = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context");
        assert!(result.is_err());
        assert_eq!(fs::read(&output_path).unwrap(), SENTINEL);
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_to_matching_content_is_not_reclaimed() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target_path = dir.path().join("target_with_marker_bytes");
        fs::write(&target_path, RESERVATION_MARKER).unwrap();

        let link_path = dir.path().join("output.pqe");
        symlink(&target_path, &link_path).unwrap();

        let result = claim_output_and_temp(link_path.to_str().unwrap(), "test claim context");
        assert!(
            result.is_err(),
            "a symlink must never be followed and reclaimed, even if its target matches exactly"
        );
        assert!(link_path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target_path).unwrap(), RESERVATION_MARKER);
    }

    #[cfg(unix)]
    #[test]
    fn test_lock_path_symlink_is_refused() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("output.pqe");
        let evil_target = dir.path().join("evil_target");
        fs::write(
            &evil_target,
            b"unrelated file pqenc must never open or lock",
        )
        .unwrap();
        symlink(&evil_target, dir.path().join("output.pqe.lock")).unwrap();

        let result = claim_output_and_temp(output_path.to_str().unwrap(), "test claim context");
        assert!(
            result.is_err(),
            "a symlinked lockfile path must be refused, never followed"
        );
        assert_eq!(
            fs::read(&evil_target).unwrap(),
            b"unrelated file pqenc must never open or lock"
        );
    }
}

// PQE3 per-segment body key derivation tests.
mod pqe3_body_key_tests {
    use super::*;

    #[test]
    fn test_derive_body_key_v3_different_segments_differ() {
        let secret = vec![0x42; SHARED_SECRET_SIZE];
        let salt = [0x33; SALT_SIZE];

        let key0 = derive_body_key_v3(&secret, &salt, 0).unwrap();
        let key1 = derive_body_key_v3(&secret, &salt, 1).unwrap();

        assert_ne!(key0.data, key1.data);
    }

    #[test]
    fn test_derive_body_key_v3_deterministic() {
        let secret = vec![0x42; SHARED_SECRET_SIZE];
        let salt = [0x33; SALT_SIZE];

        let key_a = derive_body_key_v3(&secret, &salt, 7).unwrap();
        let key_b = derive_body_key_v3(&secret, &salt, 7).unwrap();

        assert_eq!(key_a.data, key_b.data);
    }

    #[test]
    fn test_derive_body_key_v3_invalid_secret_size() {
        let short = vec![0x42; 32];
        let salt = [0x33; SALT_SIZE];

        assert!(derive_body_key_v3(&short, &salt, 0).is_err());
    }

    #[test]
    fn test_derive_body_key_v3_output_size() {
        let secret = vec![0x42; SHARED_SECRET_SIZE];
        let salt = [0x33; SALT_SIZE];

        let key = derive_body_key_v3(&secret, &salt, 0).unwrap();
        assert_eq!(key.data.len(), AES_KEY_SIZE);
    }

    #[test]
    fn test_get_nonce_same_bytes_across_segments_with_different_keys() {
        // The safety argument behind resetting the nonce counter at every
        // segment boundary: the raw nonce bytes at local_chunk_index 0 are
        // identical regardless of segment, but each segment's key differs,
        // so the (key, nonce) pair as a whole is never repeated even though
        // nonce bytes are.
        let base_nonce = [0x11u8; NONCE_SIZE];
        let nonce_segment0 = get_nonce(&base_nonce, 0).unwrap();
        let nonce_segment1 = get_nonce(&base_nonce, 0).unwrap();
        assert_eq!(nonce_segment0.as_slice(), nonce_segment1.as_slice());

        let secret = vec![0x42; SHARED_SECRET_SIZE];
        let salt = [0x33; SALT_SIZE];
        let key_segment0 = derive_body_key_v3(&secret, &salt, 0).unwrap();
        let key_segment1 = derive_body_key_v3(&secret, &salt, 1).unwrap();
        assert_ne!(key_segment0.data, key_segment1.data);
    }
}

// PQE3 body-chunk AAD tests.
mod pqe3_aad_tests {
    use super::*;

    #[test]
    fn test_build_aad_v3_differs_across_segment_index() {
        let header_hash = [0x77u8; 32];
        let aad0 = build_aad_v3(AAD_CHUNK_TYPE_NORMAL, 0, 5, &header_hash);
        let aad1 = build_aad_v3(AAD_CHUNK_TYPE_NORMAL, 1, 5, &header_hash);
        assert_ne!(aad0, aad1);
    }

    #[test]
    fn test_build_aad_v3_differs_across_local_chunk_index() {
        let header_hash = [0x77u8; 32];
        let aad_a = build_aad_v3(AAD_CHUNK_TYPE_NORMAL, 2, 0, &header_hash);
        let aad_b = build_aad_v3(AAD_CHUNK_TYPE_NORMAL, 2, 1, &header_hash);
        assert_ne!(aad_a, aad_b);
    }

    #[test]
    fn test_build_aad_v3_length_distinct_from_other_channels() {
        let header_hash = [0u8; 32];
        let aad_v3 = build_aad_v3(AAD_CHUNK_TYPE_NORMAL, 0, 0, &header_hash);
        let aad_metadata = build_metadata_aad(&header_hash);

        assert_eq!(aad_v3.len(), 50);
        assert_ne!(aad_v3.len(), aad_metadata.len());
    }

    #[test]
    fn test_build_aad_v3_version_byte() {
        let header_hash = [0u8; 32];
        let aad = build_aad_v3(AAD_CHUNK_TYPE_LAST, 3, 4, &header_hash);
        assert_eq!(aad[0], AAD_VERSION_V3);
        assert_eq!(aad[1], AAD_CHUNK_TYPE_LAST);
    }
}

// PQE3 segment/local-chunk-index arithmetic tests.
mod pqe3_segment_arithmetic_tests {
    use super::*;

    #[test]
    fn test_segment_and_local_chunk_index_within_first_segment() {
        let chunks_per_segment = 5;
        for global in 0..chunks_per_segment {
            let (segment, local) =
                segment_and_local_chunk_index(global, chunks_per_segment).unwrap();
            assert_eq!(segment, 0);
            assert_eq!(local, global);
        }
    }

    #[test]
    fn test_segment_and_local_chunk_index_at_boundary() {
        let chunks_per_segment = 5;
        let (segment, local) =
            segment_and_local_chunk_index(chunks_per_segment - 1, chunks_per_segment).unwrap();
        assert_eq!((segment, local), (0, chunks_per_segment - 1));

        let (segment, local) =
            segment_and_local_chunk_index(chunks_per_segment, chunks_per_segment).unwrap();
        assert_eq!((segment, local), (1, 0));

        let (segment, local) =
            segment_and_local_chunk_index(3 * chunks_per_segment + 2, chunks_per_segment).unwrap();
        assert_eq!((segment, local), (3, 2));
    }

    #[test]
    fn test_segment_and_local_chunk_index_real_constants() {
        assert_eq!(CHUNKS_PER_SEGMENT, 131072);
        assert!(SEGMENT_SIZE.is_multiple_of(CHUNK_SIZE as u64));

        let (segment, local) =
            segment_and_local_chunk_index(CHUNKS_PER_SEGMENT - 1, CHUNKS_PER_SEGMENT).unwrap();
        assert_eq!((segment, local), (0, CHUNKS_PER_SEGMENT - 1));

        let (segment, local) =
            segment_and_local_chunk_index(CHUNKS_PER_SEGMENT, CHUNKS_PER_SEGMENT).unwrap();
        assert_eq!((segment, local), (1, 0));
    }

    #[test]
    fn test_segment_and_local_chunk_index_rejects_zero_chunks_per_segment() {
        assert!(segment_and_local_chunk_index(0, 0).is_err());
    }
}

// End-to-end PQE3 tests: real crypto, via the real encrypt_file/decrypt_file
// (and their `_with_segment_size` variants for exercising multi-segment
// transitions without an 8 GiB fixture -- chunks_per_segment is purely a
// test-only seam, never part of the on-disk format; production always uses
// the real CHUNKS_PER_SEGMENT constant via encrypt_file/decrypt_file).
mod format_tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_PASSPHRASE: &str = "pqe3-test-passphrase";

    /// Writes `passphrase` to a file inside `dir` with owner-only
    /// permissions (required by `resolve_passphrase`, which these
    /// in-process calls to `generate_keys`/`load_private_key`/
    /// `decrypt_file*` now go through just like the CLI does) and returns
    /// its path.
    fn test_passphrase_file(dir: &std::path::Path, passphrase: &str) -> String {
        let path = dir.join("test_passphrase.txt");
        fs::write(&path, passphrase).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_str().unwrap().to_string()
    }

    /// Generates a real keypair on disk via the same `generate_keys` the CLI
    /// uses, so `encrypt_file`/`decrypt_file` (which read PEM files from
    /// paths, not in-memory keys) have real, valid inputs.
    fn generate_test_keypair(dir: &std::path::Path) -> (String, String) {
        let pub_path = dir.join("pub.pem");
        let priv_path = dir.join("priv.pem");
        generate_keys(
            pub_path.to_str().unwrap(),
            priv_path.to_str().unwrap(),
            Some(test_passphrase_file(dir, TEST_PASSPHRASE)),
        )
        .unwrap();
        (
            pub_path.to_str().unwrap().to_string(),
            priv_path.to_str().unwrap().to_string(),
        )
    }

    /// Loads a real, valid private key from `priv_path`, flips one byte of
    /// its embedded `H(ek)` (the FIPS 203 §7.3 hash-check field), and writes
    /// it back out as a plain-text (unencrypted) PEM under `dir/filename`.
    /// Composite layout is `[4-byte len][ML-KEM sk(3168)][X25519 sk(32)]`,
    /// and within the ML-KEM secret key the stored hash sits at bytes
    /// [3104, 3136) -- see `validate_private_key_only` in libcrux-ml-kem's
    /// `ind_cca.rs`. Returns the corrupted key's path.
    fn corrupt_private_key_hash(
        dir: &std::path::Path,
        priv_path: &str,
        filename: &str,
    ) -> std::path::PathBuf {
        let mut composite_priv =
            load_private_key(priv_path, Some(test_passphrase_file(dir, TEST_PASSPHRASE))).unwrap();
        composite_priv.data[4 + 3104] ^= 0xFF;

        let corrupted_path = dir.join(filename);
        fs::write(
            &corrupted_path,
            pem_encode(&composite_priv.data, PEM_PRIV_BEGIN, PEM_PRIV_END),
        )
        .unwrap();
        corrupted_path
    }

    /// Returns the on-disk header length of an already-encrypted file, by
    /// running the same `parse_header` decrypt_file/verify_file use.
    fn read_header_len(path: &std::path::Path) -> usize {
        let mut fin = File::open(path).unwrap();
        parse_header(&mut fin).unwrap().header_bytes.len()
    }

    /// Recomputes the (unauthenticated) SHA-256 checksum trailer over
    /// tampered bytes so a tampering test isolates and proves AEAD-level
    /// rejection -- the actual security mechanism -- rather than
    /// incidentally being caught by the plain corruption-detection checksum
    /// first. See the module doc comment's "Accepted Risks"/checksum-trailer
    /// notes: the trailer is never a security control.
    fn rewrite_checksum_trailer(bytes: &mut [u8]) {
        use sha2::Digest;
        let body_len = bytes.len() - TRAILER_SIZE;
        let (body, trailer) = bytes.split_at_mut(body_len);
        let digest: [u8; TRAILER_SIZE] = Sha256::digest(&body[..]).into();
        trailer.copy_from_slice(&digest);
    }

    #[test]
    fn test_pqe4_encrypt_writes_v4_magic() {
        let dir = TempDir::new().unwrap();
        let (pub_path, _priv_path) = generate_test_keypair(dir.path());
        let input_path = dir.path().join("input.txt");
        fs::write(&input_path, b"hello pqe4").unwrap();
        let output_path = dir.path().join("output.pqe");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();

        let bytes = fs::read(&output_path).unwrap();
        assert_eq!(&bytes[..4], MAGIC_V4);
    }

    #[test]
    fn test_pqe4_roundtrip_empty() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let input_path = dir.path().join("empty.bin");
        fs::write(&input_path, b"").unwrap();
        let output_path = dir.path().join("empty.pqe");
        let restored_path = dir.path().join("empty_out.bin");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();
        decrypt_file(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
        )
        .unwrap();

        assert_eq!(fs::read(&restored_path).unwrap(), b"");
    }

    #[test]
    fn test_pqe4_roundtrip_single_chunk() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0x11u8; 1234];
        let input_path = dir.path().join("single.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("single.pqe");
        let restored_path = dir.path().join("single_out.bin");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();
        decrypt_file(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
        )
        .unwrap();

        assert_eq!(fs::read(&restored_path).unwrap(), plaintext);
    }

    #[test]
    fn test_pqe4_roundtrip_multichunk_single_segment() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0xABu8; 3 * CHUNK_SIZE + 777];
        let input_path = dir.path().join("multi.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("multi.pqe");
        let restored_path = dir.path().join("multi_out.bin");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();
        decrypt_file(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
        )
        .unwrap();

        assert_eq!(fs::read(&restored_path).unwrap(), plaintext);
    }

    #[test]
    fn test_pqe4_roundtrip_multi_segment_transition() {
        // chunks_per_segment = 2 with 5 chunks of plaintext (4 full +
        // 1 partial) produces segments of sizes [2, 2, 1] -- a full
        // segment-boundary rekey and a short final segment together.
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0x5Au8; 4 * CHUNK_SIZE + 555];
        let input_path = dir.path().join("multi_segment.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("multi_segment.pqe");
        let restored_path = dir.path().join("multi_segment_out.bin");

        encrypt_file_with_segment_size(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
            2,
        )
        .unwrap();
        decrypt_file_with_segment_size(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
            2,
        )
        .unwrap();

        assert_eq!(fs::read(&restored_path).unwrap(), plaintext);
    }

    #[test]
    fn test_pqe4_tampering_chunk_swapped_across_segments() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0x5Au8; 4 * CHUNK_SIZE + 555];
        let input_path = dir.path().join("swap_in.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("swap.pqe");

        encrypt_file_with_segment_size(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
            2,
        )
        .unwrap();

        let header_len = read_header_len(&output_path);
        let encrypted_chunk_size = CHUNK_SIZE + TAG_SIZE;
        let mut bytes = fs::read(&output_path).unwrap();

        // Chunk 0 (segment 0, local 0) and chunk 2 (segment 1, local 0) are
        // both full-size chunks -- same length, so swapping them in place
        // leaves the file's total size and every other chunk's position
        // unaffected, isolating the tamper to exactly a cross-segment
        // cut-and-paste.
        let chunk0_start = header_len;
        let chunk2_start = header_len + 2 * encrypted_chunk_size;
        let (left, right) = bytes.split_at_mut(chunk2_start);
        left[chunk0_start..chunk0_start + encrypted_chunk_size]
            .swap_with_slice(&mut right[..encrypted_chunk_size]);

        rewrite_checksum_trailer(&mut bytes);
        fs::write(&output_path, &bytes).unwrap();

        let restored_path = dir.path().join("swap_out.bin");
        let result = decrypt_file_with_segment_size(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
            2,
        );
        assert!(
            result.is_err(),
            "swapping ciphertext chunks across segments must fail AEAD verification \
            even with a matching checksum trailer"
        );
    }

    #[test]
    fn test_pqe4_tampering_corrupted_final_tag() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0x5Au8; 4 * CHUNK_SIZE + 555];
        let input_path = dir.path().join("tag_in.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("tag.pqe");

        encrypt_file_with_segment_size(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
            2,
        )
        .unwrap();

        let mut bytes = fs::read(&output_path).unwrap();
        // The final chunk's 16-byte AEAD tag is the TRAILER_SIZE bytes
        // immediately before the checksum trailer at the end of the file.
        let tag_byte = bytes.len() - TRAILER_SIZE - 1;
        bytes[tag_byte] ^= 0xFF;
        rewrite_checksum_trailer(&mut bytes);
        fs::write(&output_path, &bytes).unwrap();

        let restored_path = dir.path().join("tag_out.bin");
        let result = decrypt_file_with_segment_size(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
            2,
        );
        assert!(
            result.is_err(),
            "a corrupted final-chunk tag must fail AEAD verification"
        );
    }

    #[test]
    fn test_pqe4_tampering_truncated_body() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let plaintext = vec![0x5Au8; 4 * CHUNK_SIZE + 555];
        let input_path = dir.path().join("trunc_in.bin");
        fs::write(&input_path, &plaintext).unwrap();
        let output_path = dir.path().join("trunc.pqe");

        encrypt_file_with_segment_size(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
            2,
        )
        .unwrap();

        let mut bytes = fs::read(&output_path).unwrap();
        bytes.truncate(bytes.len() - 100);
        fs::write(&output_path, &bytes).unwrap();

        let restored_path = dir.path().join("trunc_out.bin");
        let result = decrypt_file_with_segment_size(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
            2,
        );
        assert!(
            result.is_err(),
            "truncated PQE4 body must be rejected cleanly, not panic"
        );
    }

    #[test]
    fn test_pqe4_tampering_corrupted_checksum_trailer() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let input_path = dir.path().join("trailer_in.bin");
        fs::write(&input_path, b"some pqe4 content").unwrap();
        let output_path = dir.path().join("trailer.pqe");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();

        let mut bytes = fs::read(&output_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&output_path, &bytes).unwrap();

        let restored_path = dir.path().join("trailer_out.bin");
        let result = decrypt_file(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            &priv_path,
            Some(test_passphrase_file(dir.path(), TEST_PASSPHRASE)),
        );
        let err = result.expect_err("corrupted trailer must fail the verify preflight");
        assert!(
            format!("{err:#}").contains("CHECKSUM MISMATCH"),
            "unexpected error: {err:#}"
        );
        assert!(!restored_path.exists());
    }

    #[test]
    fn test_encrypt_rejects_invalid_public_key() {
        let dir = TempDir::new().unwrap();

        // Same-length-but-invalid ML-KEM public key: passes every size
        // check but fails the FIPS 203 §7.2 canonical-encoding check.
        // All-0xFF bytes pack to the maximum 12-bit value (4095) for every
        // coefficient, which is >= q (3329), so none of them are canonically
        // reduced -- unlike the security review's own repeated-0x42 fixture,
        // which (checked empirically) happens to already be canonical and
        // so is unsuitable here.
        let mlkem_pk = vec![0xFFu8; MLKEM1024_PUBLIC_KEY_SIZE];
        let x25519_pk = [0x33u8; 32];
        let mut composite_pub = Vec::new();
        composite_pub.extend_from_slice(&(mlkem_pk.len() as u32).to_be_bytes());
        composite_pub.extend_from_slice(&mlkem_pk);
        composite_pub.extend_from_slice(&x25519_pk);

        let bad_pub_path = dir.path().join("bad_pub.pem");
        fs::write(
            &bad_pub_path,
            pem_encode(&composite_pub, PEM_PUB_BEGIN, PEM_PUB_END),
        )
        .unwrap();

        let input_path = dir.path().join("pubkey_in.bin");
        fs::write(&input_path, b"some content").unwrap();
        let output_path = dir.path().join("pubkey_out.pqe");

        let result = encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            bad_pub_path.to_str().unwrap(),
        );
        let err = result.expect_err("a non-canonical ML-KEM public key must be rejected");
        assert!(
            format!("{err:#}").contains("Invalid ML-KEM public key"),
            "unexpected error: {err:#}"
        );
        assert!(!output_path.exists());
    }

    #[test]
    fn test_decrypt_rejects_corrupted_private_key_hash() {
        let dir = TempDir::new().unwrap();
        let (pub_path, priv_path) = generate_test_keypair(dir.path());
        let input_path = dir.path().join("priv_corrupt_in.bin");
        fs::write(&input_path, b"some content").unwrap();
        let output_path = dir.path().join("priv_corrupt.pqe");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();

        let corrupted_priv_path =
            corrupt_private_key_hash(dir.path(), &priv_path, "corrupted_priv.pem");

        let restored_path = dir.path().join("priv_corrupt_out.bin");
        let result = decrypt_file(
            output_path.to_str().unwrap(),
            Some(restored_path.to_str().unwrap()),
            corrupted_priv_path.to_str().unwrap(),
            None,
        );
        let err = result.expect_err("a private key failing the FIPS 203 hash check must be rejected");
        assert!(
            format!("{err:#}").contains("Invalid ML-KEM private key"),
            "unexpected error: {err:#}"
        );
        assert!(!restored_path.exists());
    }

    #[test]
    fn test_fingerprint_rejects_corrupted_private_key_hash() {
        let dir = TempDir::new().unwrap();
        let (_pub_path, priv_path) = generate_test_keypair(dir.path());

        let corrupted_priv_path =
            corrupt_private_key_hash(dir.path(), &priv_path, "fp_corrupted_priv.pem");

        let result = show_fingerprint(
            corrupted_priv_path.to_str().unwrap().to_string(),
            None,
        );
        let err = result.expect_err("a private key failing the FIPS 203 hash check must be rejected");
        assert!(
            format!("{err:#}").contains("Invalid ML-KEM private key"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_verify_open_file_recognizes_pqe4() {
        let dir = TempDir::new().unwrap();
        let (pub_path, _priv_path) = generate_test_keypair(dir.path());
        let input_path = dir.path().join("verify_in.bin");
        fs::write(&input_path, b"verify me").unwrap();
        let output_path = dir.path().join("verify.pqe");

        encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            &pub_path,
        )
        .unwrap();

        let mut fin = File::open(&output_path).unwrap();
        let verified = verify_open_file(&mut fin, output_path.to_str().unwrap()).unwrap();
        assert_eq!(&verified.parsed.header_bytes[..4], MAGIC_V4);
        assert_eq!(verified.parsed.format, FileFormat::V4);
    }

    #[test]
    fn test_verify_open_file_recognizes_pqe3() {
        // Legacy format, built directly via build_test_pqe3_file rather
        // than the real encrypt_file (which only ever writes PQE4 now) --
        // pairs with test_verify_open_file_recognizes_pqe4 above to make
        // verify's dual-format support an explicit, named assertion.
        let (file_bytes, _priv_pem) = build_test_pqe3_file(&[], b"legacy verify me", true);
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("legacy_verify.pqe");
        fs::write(&input_path, &file_bytes).unwrap();

        let mut fin = File::open(&input_path).unwrap();
        let verified = verify_open_file(&mut fin, input_path.to_str().unwrap()).unwrap();
        assert_eq!(&verified.parsed.header_bytes[..4], MAGIC_V3);
        assert_eq!(verified.parsed.format, FileFormat::V3);
    }

    #[test]
    fn test_pqe3_legacy_file_decrypts_after_pqe4_migration() {
        // encrypt_file only ever writes PQE4 now, but decrypt_file must
        // still accept a genuine PQE3 file (hand-built via
        // build_test_pqe3_file, independent of whatever encrypt_file
        // currently emits), including recovering its embedded filename and
        // timestamps -- the dual-format guarantee, as an explicit, named
        // regression test rather than an incidental byproduct of other
        // traversal/trailer-focused tests.
        let dir = TempDir::new().unwrap();
        let mtime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(1_700_000_000, 0));
        let atime_bytes = encode_timestamp(filetime::FileTime::from_unix_time(1_700_000_100, 0));
        let (file_bytes, priv_pem) = build_test_pqe3_file(
            &[
                (METADATA_FIELD_FILENAME, b"legacy_report.txt"),
                (METADATA_FIELD_MTIME, &mtime_bytes),
                (METADATA_FIELD_ATIME, &atime_bytes),
            ],
            b"legacy pqe3 content",
            true,
        );

        let input_path = dir.path().join("legacy.pqe");
        fs::write(&input_path, &file_bytes).unwrap();
        let priv_path = dir.path().join("priv.pem");
        fs::write(&priv_path, &priv_pem).unwrap();

        decrypt_file(input_path.to_str().unwrap(), None, priv_path.to_str().unwrap(), None)
            .unwrap();

        let restored_path = dir.path().join("legacy_report.txt");
        assert!(
            restored_path.exists(),
            "expected output restored via embedded PQE3 filename at {:?}",
            restored_path
        );

        // Checked before the content read below: on Linux, reading a file
        // whose atime is more than a day older than its mtime (relatime
        // default) bumps atime to now, which would make this assertion
        // observe the read itself rather than the restored value.
        let restored_meta = fs::metadata(&restored_path).unwrap();
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&restored_meta),
            filetime::FileTime::from_unix_time(1_700_000_000, 0)
        );
        assert_eq!(
            filetime::FileTime::from_last_access_time(&restored_meta),
            filetime::FileTime::from_unix_time(1_700_000_100, 0)
        );

        assert_eq!(fs::read(&restored_path).unwrap(), b"legacy pqe3 content");
    }

    #[test]
    fn test_decrypt_rejects_traversal_in_embedded_filename_pqe3() {
        // SECURITY: a hostile sender (anyone holding the recipient's
        // public key) embeds a path-traversal filename. Decrypt must
        // never honor it -- it must fall back to .pqe-suffix stripping,
        // and must never write outside the input file's own directory.
        let dir = TempDir::new().unwrap();
        let (file_bytes, priv_pem) = build_test_pqe3_file(
            &[(METADATA_FIELD_FILENAME, b"../../evil")],
            b"malicious sender content",
            true,
        );

        let sub_dir = dir.path().join("archive");
        fs::create_dir(&sub_dir).unwrap();
        let input_path = sub_dir.join("backup.pqe");
        fs::write(&input_path, &file_bytes).unwrap();
        let priv_path = dir.path().join("priv.pem");
        fs::write(&priv_path, &priv_pem).unwrap();

        let result = decrypt_file(
            input_path.to_str().unwrap(),
            None,
            priv_path.to_str().unwrap(),
            None,
        );
        assert!(result.is_ok(), "{:?}", result.err());

        // Falls back to .pqe-suffix stripping, in the SAME directory as the input.
        let expected_output = sub_dir.join("backup");
        assert!(
            expected_output.exists(),
            "expected fallback output at {:?}",
            expected_output
        );
        assert_eq!(
            fs::read(&expected_output).unwrap(),
            b"malicious sender content"
        );

        // The naive traversal target ("../../evil" joined onto the
        // input's directory, i.e. two levels up) must never be created.
        let traversal_target = dir.path().parent().unwrap().join("evil");
        assert!(
            !traversal_target.exists(),
            "path traversal target must not exist: {:?}",
            traversal_target
        );
    }

    #[test]
    fn test_decrypt_rejects_traversal_in_embedded_filename_pqe4() {
        // Same guarantee as the PQE3 version above, but through PQE4's
        // entirely different metadata code path: chunk 0 is decrypted and
        // manually split (main.rs's decrypt_file_with_segment_size,
        // FileFormat::V4 arm) instead of a standalone metadata AEAD call,
        // so this isn't redundant coverage -- it exercises different code.
        let dir = TempDir::new().unwrap();
        let (file_bytes, priv_pem) = build_test_pqe4_file(
            &[(METADATA_FIELD_FILENAME, b"../../evil")],
            b"malicious sender content",
            true,
        );

        let sub_dir = dir.path().join("archive");
        fs::create_dir(&sub_dir).unwrap();
        let input_path = sub_dir.join("backup.pqe");
        fs::write(&input_path, &file_bytes).unwrap();
        let priv_path = dir.path().join("priv.pem");
        fs::write(&priv_path, &priv_pem).unwrap();

        let result = decrypt_file(
            input_path.to_str().unwrap(),
            None,
            priv_path.to_str().unwrap(),
            None,
        );
        assert!(result.is_ok(), "{:?}", result.err());

        let expected_output = sub_dir.join("backup");
        assert!(
            expected_output.exists(),
            "expected fallback output at {:?}",
            expected_output
        );
        assert_eq!(
            fs::read(&expected_output).unwrap(),
            b"malicious sender content"
        );

        let traversal_target = dir.path().parent().unwrap().join("evil");
        assert!(
            !traversal_target.exists(),
            "path traversal target must not exist: {:?}",
            traversal_target
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_decrypt_falls_back_safely_for_windows_unsafe_embedded_filename_pqe3() {
        // SECURITY: on Windows, PathBuf::join/push treats a drive-relative
        // name like "C:restore.txt" specially -- per the stdlib docs, "if
        // `path` has a prefix but no root, it replaces `self`" -- so
        // naively joining it onto the input file's directory would
        // silently discard that directory and resolve against the CWD of
        // whatever drive the embedded name names, nowhere near the
        // encrypted input. Rejection must make decrypt fall back to the
        // same .pqe-stripped sibling path the pure traversal tests above
        // assert on -- never attempt (or silently succeed at) writing
        // anywhere else. Deliberately does not touch the real C:\ drive or
        // change the process's actual cwd -- both unsafe in a parallel test
        // binary -- because a correct fix never gets far enough to try.
        for malicious_name in ["C:restore.txt", "restore.txt:hidden.exe", "CON", "evil."] {
            let dir = TempDir::new().unwrap();
            let (file_bytes, priv_pem) = build_test_pqe3_file(
                &[(METADATA_FIELD_FILENAME, malicious_name.as_bytes())],
                b"malicious sender content",
                true,
            );

            let sub_dir = dir.path().join("archive");
            fs::create_dir(&sub_dir).unwrap();
            let input_path = sub_dir.join("backup.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let result = decrypt_file(
                input_path.to_str().unwrap(),
                None,
                priv_path.to_str().unwrap(),
                None,
            );
            assert!(result.is_ok(), "{:?} -> {:?}", malicious_name, result.err());

            let expected_output = sub_dir.join("backup");
            assert!(
                expected_output.exists(),
                "expected fallback output at {:?} for embedded name {:?}",
                expected_output,
                malicious_name
            );
            assert_eq!(
                fs::read(&expected_output).unwrap(),
                b"malicious sender content"
            );

            // Nothing besides the input, the fallback output, and its
            // sibling lock file (left behind by design -- see
            // acquire_output_lock's doc comment: pqenc never deletes it)
            // may exist: proves rejection actually prevented an attempted
            // write under the malicious name, not just that some other
            // file happened to win.
            let entries: std::collections::BTreeSet<String> = fs::read_dir(&sub_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            let expected: std::collections::BTreeSet<String> =
                ["backup.pqe", "backup", "backup.lock"]
                    .into_iter()
                    .map(String::from)
                    .collect();
            assert_eq!(
                entries, expected,
                "unexpected extra file for embedded name {:?}: {:?}",
                malicious_name, entries
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_decrypt_falls_back_safely_for_windows_unsafe_embedded_filename_pqe4() {
        // Same guarantee via PQE4's different metadata code path -- see the
        // pqe3/pqe4 traversal test pair above for why this isn't redundant
        // coverage.
        for malicious_name in ["C:restore.txt", "restore.txt:hidden.exe", "CON", "evil."] {
            let dir = TempDir::new().unwrap();
            let (file_bytes, priv_pem) = build_test_pqe4_file(
                &[(METADATA_FIELD_FILENAME, malicious_name.as_bytes())],
                b"malicious sender content",
                true,
            );

            let sub_dir = dir.path().join("archive");
            fs::create_dir(&sub_dir).unwrap();
            let input_path = sub_dir.join("backup.pqe");
            fs::write(&input_path, &file_bytes).unwrap();
            let priv_path = dir.path().join("priv.pem");
            fs::write(&priv_path, &priv_pem).unwrap();

            let result = decrypt_file(
                input_path.to_str().unwrap(),
                None,
                priv_path.to_str().unwrap(),
                None,
            );
            assert!(result.is_ok(), "{:?} -> {:?}", malicious_name, result.err());

            let expected_output = sub_dir.join("backup");
            assert!(expected_output.exists());
            assert_eq!(
                fs::read(&expected_output).unwrap(),
                b"malicious sender content"
            );

            // See the matching comment in the pqe3 test above: the sibling
            // lock file is left behind by design and expected here too.
            let entries: std::collections::BTreeSet<String> = fs::read_dir(&sub_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            let expected: std::collections::BTreeSet<String> =
                ["backup.pqe", "backup", "backup.lock"]
                    .into_iter()
                    .map(String::from)
                    .collect();
            assert_eq!(entries, expected);
        }
    }

    #[test]
    fn test_decrypt_rejects_missing_checksum_trailer_marker() {
        // The checksum trailer marker is mandatory now that PQE1/PQE2
        // (which could legitimately lack one) are gone: a file whose
        // extension region omits it must be rejected outright, not
        // silently tolerated as "structure-only, checksum skipped".
        let dir = TempDir::new().unwrap();
        let (file_bytes, priv_pem) = build_test_pqe3_file(&[], b"no trailer here", false);

        let input_path = dir.path().join("no_trailer.pqe");
        fs::write(&input_path, &file_bytes).unwrap();
        let priv_path = dir.path().join("priv.pem");
        fs::write(&priv_path, &priv_pem).unwrap();

        let result = decrypt_file(
            input_path.to_str().unwrap(),
            None,
            priv_path.to_str().unwrap(),
            None,
        );
        let err = result.expect_err("decrypt must reject a file missing the checksum trailer");
        assert!(
            format!("{err:#}").contains("checksum trailer"),
            "unexpected error: {err:#}"
        );
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
        let dir = TempDir::new().unwrap();
        let plaintext = vec![0x42u8; (2 * CHUNK_SIZE) + 999];
        let (file_bytes, _priv_pem) = build_test_pqe3_file(&[], &plaintext, true);

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
        assert_eq!(
            body, expected_body,
            "reused handle must read back the exact verified body bytes"
        );
    }
}

// Windows-only filename-sanitization hardening: exercises the additional
// rejections `sanitize_embedded_filename` (via `filename_unsafe_on_windows`)
// applies on Windows only -- drive-relative/prefixed names, NTFS Alternate
// Data Stream syntax, reserved MS-DOS device basenames, and trailing
// dot/space -- none of which are unsafe (or even meaningful) on Unix, so
// they can't live in the shared, non-cfg-gated `metadata_tests` module
// without producing false failures on non-Windows CI runners. See
// `windows_acl_tests` below for why this only runs when actually compiled
// and executed on Windows (the CI `windows-latest` runner, or a real
// Windows machine).
#[cfg(windows)]
mod windows_filename_tests {
    use super::*;

    #[test]
    fn test_sanitize_rejects_drive_relative_and_prefixed_names() {
        for bad in ["C:restore.txt", "C:\\restore.txt", "c:evil", "z:x"] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject {:?} on Windows",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_rejects_alternate_data_stream_syntax() {
        for bad in ["evil.txt:hidden.exe", "report.pdf:secret"] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject ADS syntax {:?} on Windows",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_rejects_reserved_device_basenames() {
        for bad in [
            "CON", "con", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9",
            "NUL.txt", "con.tar.gz", "Com3.log", "COM\u{b9}", "LPT\u{b2}",
        ] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject reserved device name {:?} on Windows",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_rejects_other_reserved_characters() {
        for bad in ["a<b", "a>b", "a\"b", "a|b", "a?b", "a*b", "a\tb", "a\x01b"] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject reserved character in {:?} on Windows",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_rejects_trailing_dot_or_space() {
        for bad in ["evil.", "evil ", "report.pdf.", "report.pdf "] {
            assert!(
                sanitize_embedded_filename(bad).is_none(),
                "should reject trailing dot/space {:?} on Windows",
                bad
            );
        }
    }

    #[test]
    fn test_sanitize_still_accepts_ordinary_names_on_windows() {
        // Regression guard: the new Windows-only checks must not reject
        // ordinary filenames a real `encrypt_file` run would embed.
        for good in ["report.pdf", "my archive.tar.gz", "IMG_0001.JPG", "backup.tar.gz"] {
            assert_eq!(sanitize_embedded_filename(good).as_deref(), Some(good));
        }
    }

    #[test]
    fn test_resolve_decrypt_output_falls_back_for_drive_relative_name() {
        // Pure string/Path logic -- no filesystem I/O, so nothing here
        // touches the real C:\ drive or the process's actual cwd.
        let resolved =
            resolve_decrypt_output("C:\\archive\\backup.pqe", Some("C:restore.txt")).unwrap();
        assert_eq!(resolved, "C:\\archive\\backup");
    }
}

// Windows DACL hardening: these tests only run when actually compiled and
// executed on Windows (the CI `windows-latest` runner, or a real Windows
// machine) -- there is nothing to check on Unix, where file permissions are
// covered separately (see `test_encrypted_output_permissions` and
// `test_generate_keys_key_file_permissions` in tests/integration_tests.rs).
#[cfg(windows)]
mod windows_acl_tests {
    use super::*;
    use std::collections::HashSet;
    use std::os::windows::ffi::OsStrExt;
    use tempfile::TempDir;

    /// Returns the set of grantee SIDs (as `S-1-5-...` strings) present in
    /// `path`'s DACL, and whether that DACL is marked protected
    /// (`SE_DACL_PROTECTED`, i.e. not merging in ACEs inherited from the
    /// parent directory). This reads back the raw Win32 security
    /// descriptor rather than re-deriving the expected SDDL string, so it
    /// actually exercises what `create_owner_only` produced instead of
    /// just echoing its own logic back.
    fn read_dacl(path: &std::path::Path) -> (HashSet<String>, bool) {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        };

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
        assert_eq!(
            err, 0,
            "GetNamedSecurityInfoW failed with Win32 error {err}"
        );

        let mut sids = HashSet::new();
        let ace_count = unsafe { (*dacl).AceCount };
        for i in 0..u32::from(ace_count) {
            let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            assert_ne!(
                unsafe { GetAce(dacl, i, &mut ace_ptr) },
                0,
                "GetAce failed for index {i}"
            );
            let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
            // ACCESS_ALLOWED_ACE_TYPE (WinNT.h) == 0. This DACL is built
            // from an SDDL string containing only "(A;;FA;;;...)" entries,
            // so anything else here is an unexpected ACE and should fail
            // the test loudly rather than be silently skipped.
            assert_eq!(
                header.AceType, 0,
                "expected only ACCESS_ALLOWED_ACE entries in this DACL"
            );
            let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
            let sid_ptr = std::ptr::addr_of!(ace.SidStart) as windows_sys::Win32::Security::PSID;
            sids.insert(windows_security::sid_to_string(sid_ptr).unwrap());
        }

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) },
            0,
            "GetSecurityDescriptorControl failed"
        );
        let protected = control & SE_DACL_PROTECTED != 0;

        unsafe { LocalFree(sd as _) };
        (sids, protected)
    }

    #[test]
    fn owner_only_mode_gets_hardened_protected_dacl() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.bin");
        let _f = create_new_exclusive(path.to_str().unwrap(), OWNER_ONLY_MODE).unwrap();

        let (sids, protected) = read_dacl(&path);
        let expected: HashSet<String> = [
            windows_security::current_user_sid_string().unwrap(),
            "S-1-5-18".to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            sids, expected,
            "DACL must grant access to exactly {{current user, SYSTEM}} -- no more, no less"
        );
        assert!(
            protected,
            "DACL must be protected so the parent directory's ACEs cannot merge in"
        );
    }

    #[test]
    fn distributable_mode_is_not_hardened() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("public.key");
        let _f = create_new_exclusive(path.to_str().unwrap(), DISTRIBUTABLE_MODE).unwrap();

        let (_sids, protected) = read_dacl(&path);
        assert!(
            !protected,
            "DISTRIBUTABLE_MODE must keep deferring to the parent directory's ACL, \
            not get the owner-only protected DACL"
        );
    }
}
