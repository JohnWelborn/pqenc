# Testing Guide

This project includes a comprehensive test suite covering unit, integration,
security, checksum-verification, property-based, and CLI testing. Suite
sizes aren't hard-coded here — they drift every time tests are added; run
`cargo test` to see the current total, or `cargo test -- --list` for the
full list.

## Quick Start

```bash
# Run all tests
cargo test
```

## Run Specific Test Suites

```bash
# Unit tests only (tests private functions)
cargo test --bin pqenc

# Integration tests only (full encrypt/decrypt workflows)
cargo test --test integration_tests

# Security tests only (attack resistance)
cargo test --test security_tests

# Verify tests only (checksum-trailer validation, decrypt's verify preflight)
cargo test --test verify_tests

# Property-based tests only (randomized inputs)
cargo test --test property_tests

# CLI tests only (directory encryption via tar piping, Unix only)
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

### Unit Tests (`src/tests.rs`)
Tests internal utility functions and crypto operations:
- PEM encoding/decoding
- Passphrase derivation (Argon2id)
- Private key encryption/decryption
- Composite key parsing (ML-KEM-1024 + X25519)
- AES key derivation (HKDF)
- Nonce generation
- Key fingerprinting
- PQE2 metadata encoding/decoding (filename, mtime, atime)
- PQE2 file format parsing and decrypt behavior
- Output-path claim / temp-file guard ordering
- Stale reservation-placeholder reclaim logic

### Integration Tests (`tests/integration_tests.rs`)
Tests full encrypt/decrypt workflows via the CLI:
- Full workflow with small, empty, large, and exact-chunk-boundary files
- SHA-256 checksum matching before encryption and after decryption
- Wrong passphrase rejection
- File format validation (magic bytes)
- Output-path collision handling: refusing an existing destination, leaving
  no leftover temp file on success, and reclaiming a killed-mid-stream
  placeholder on retry
- Key-generation edge cases: occupied output path, identical public/private
  paths, cleanup after a partial write failure, file permissions, and the
  printed fingerprint/randomart
- `pqenc fingerprint` command behavior
- Metadata restoration (original mtime) and optional `--output` defaults

### Security Tests (`tests/security_tests.rs`)
Tests attack resistance and security properties:
- Truncation attack detection
- Bit flip attack detection
- Header and ciphertext tampering detection
- Non-deterministic encryption
- Invalid magic bytes rejection
- Encrypted output does not leak plaintext content or the original filename

### Verify Tests (`tests/verify_tests.rs`)
Tests `pqenc verify`'s checksum-trailer validation and `pqenc decrypt`'s
automatic verify preflight:
- Valid files pass; corrupted trailer, body, or header is detected
- Trailer-removal detection and rejection of invalid magic bytes/missing files
- Backward compatibility with pre-trailer-format files
- `pqenc decrypt` runs verify first and reports both stages, failing before
  decryption starts on a bad file, and refusing an occupied output path
  before paying for the full-file scan

### CLI Tests (`tests/cli_encrypt_dir.rs`)
Tests directory encryption via tar piping (Unix only):
- Encrypt a directory using `tar czf - dir | pqenc encrypt --encrypt /dev/stdin`
- Encrypt a directory using the `-` stdin shorthand

### Property-Based Tests (`tests/property_tests.rs`)
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
