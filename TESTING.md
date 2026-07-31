# Testing Guide

This project includes a comprehensive test suite with 41 tests covering unit, integration, security, property-based, and CLI testing.

## Quick Start

```bash
# Run all tests
cargo test
```

## Run Specific Test Suites

```bash
# Unit tests only (24 tests - tests private functions)
cargo test --bin pqenc

# Integration tests only (6 tests - full encrypt/decrypt workflows)
cargo test --test integration_tests

# Security tests only (6 tests - attack resistance)
cargo test --test security_tests

# Property-based tests only (3 tests - randomized inputs)
cargo test --test property_tests

# CLI tests only (2 tests - directory encryption via tar piping, Unix only)
cargo test --test cli_encrypt_dir
```

## Run Tests with Output

```bash
# Show output from passing tests
cargo test -- --nocapture

# Show output for specific test
cargo test test_full_workflow_small_file -- --nocapture
```

## Benchmarks

```bash
# Run performance benchmarks
cargo bench
```

## Test Coverage

### Unit Tests (24 tests in `src/tests.rs`)
Tests internal utility functions and crypto operations:
- PEM encoding/decoding
- Passphrase derivation (Argon2id)
- Private key encryption/decryption
- Composite key parsing (ML-KEM-1024 + X25519)
- AES key derivation (HKDF)
- Nonce generation

### Integration Tests (6 tests in `tests/integration_tests.rs`)
Tests full encrypt/decrypt workflows via the CLI:
- Full workflow with small files
- Empty file handling
- Chunk boundary cases (64KB chunks)
- Large multi-chunk files (10MB)
- Wrong passphrase rejection
- File format validation (magic bytes)

### Security Tests (6 tests in `tests/security_tests.rs`)
Tests attack resistance and security properties:
- Truncation attack detection
- Bit flip attack detection
- Non-deterministic encryption
- Invalid magic bytes rejection
- Header tampering detection
- Ciphertext tampering detection

### CLI Tests (2 tests in `tests/cli_encrypt_dir.rs`)
Tests directory encryption via tar piping (Unix only):
- Encrypt a directory using `tar czf - dir | pqenc encrypt --encrypt /dev/stdin`
- Encrypt a directory using the `-` stdin shorthand

### Property-Based Tests (3 tests in `tests/property_tests.rs`)
Tests with randomized inputs using proptest:
- Random data sizes (1 byte to 1 MB)
- Multiple chunk boundaries (1-20 chunks)
- Near-boundary variations

## Test Implementation Notes

### Passphrase Handling in Tests
Integration and security tests supply the private-key passphrase non-interactively via `pqenc`'s `--passphrase` flag, so no interactive prompt (and no external `expect` dependency) is involved. The test helpers in `tests/helpers/` wrap this in `generate_keys_with_passphrase`/`decrypt_file_with_passphrase`.

### Test Data Generation
The `TestData` helper in `tests/helpers/test_data.rs` provides utilities for generating:
- Random data of any size
- Zero-filled data
- Text data
- Large files (megabytes)

### Temporary Test Environments
The `TempTestEnv` helper in `tests/helpers/temp_files.rs` manages:
- Temporary directories (auto-cleaned on drop)
- Key generation with passphrases
- File creation
- Encryption/decryption workflows
