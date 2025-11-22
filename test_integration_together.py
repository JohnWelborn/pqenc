#!/usr/bin/env python3
"""
Comprehensive Python ↔ Rust Interoperability Tests

Tests bidirectional encryption/decryption between Python and Rust implementations
to ensure complete file format compatibility.
"""

import os
import hashlib
import subprocess
import sys
import shutil

# Configuration
RUST_BINARY = "./pqenc_rust/target/release/pqenc"
PYTHON_SCRIPT = "./pqenc.py"
PYTHON_INTERPRETER = "/opt/.venv/bin/python3"
TEST_DIR = "test_data_interop"

def run_command(cmd, expect_failure=False):
    """Execute a command and handle output."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if not expect_failure and result.returncode != 0:
        print(f"❌ Command failed with code {result.returncode}")
        print("Stdout:", result.stdout)
        print("Stderr:", result.stderr)
        sys.exit(1)
    elif expect_failure and result.returncode == 0:
        print(f"❌ Command succeeded but failure was expected")
        sys.exit(1)

    return result

def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()

def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)

def print_step(step_num, description):
    """Print a test step."""
    print(f"\n--- Step {step_num}: {description} ---")

def verify_hash(actual_file, expected_hash, description):
    """Verify file hash matches expected value."""
    actual_hash = calculate_hash(actual_file)
    if actual_hash == expected_hash:
        print(f"✅ SUCCESS: {description}")
        print(f"   Hash: {actual_hash}")
        return True
    else:
        print(f"❌ FAILURE: {description}")
        print(f"   Expected: {expected_hash}")
        print(f"   Got:      {actual_hash}")
        sys.exit(1)

def main():
    print_section("Python ↔ Rust Interoperability Tests")

    # Setup test directory
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)

    # File paths
    pub_key = f"{TEST_DIR}/pub.key"
    priv_key = f"{TEST_DIR}/priv.key"
    original_file = f"{TEST_DIR}/original.dat"

    # Python-encrypted files
    py_encrypted = f"{TEST_DIR}/python_encrypted.enc"
    py_decrypted_by_rust = f"{TEST_DIR}/python_encrypted_rust_decrypted.dat"

    # Rust-encrypted files
    rust_encrypted = f"{TEST_DIR}/rust_encrypted.enc"
    rust_decrypted_by_python = f"{TEST_DIR}/rust_encrypted_python_decrypted.dat"

    # Cross-check: each impl can decrypt its own
    py_self_decrypted = f"{TEST_DIR}/python_self_decrypted.dat"
    rust_self_decrypted = f"{TEST_DIR}/rust_self_decrypted.dat"

    # ========================================================================
    # SETUP: Generate Keys and Test File
    # ========================================================================
    print_section("Setup Phase")

    print_step(1, "Generate Keypair (Python)")
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --generate-keys --public-key {pub_key} --private-key {priv_key}")
    print("✅ Keypair generated")

    print_step(2, "Create Test File (10MB)")
    with open(original_file, 'wb') as f:
        f.write(os.urandom(10 * 1024 * 1024))
    original_hash = calculate_hash(original_file)
    print(f"✅ Test file created")
    print(f"   Original Hash: {original_hash}")

    # ========================================================================
    # TEST 1: Python Encrypts → Rust Decrypts
    # ========================================================================
    print_section("Test 1: Python Encrypt → Rust Decrypt")

    print_step("1.1", "Encrypt with Python")
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --encrypt {original_file} --output {py_encrypted} --public-key {pub_key}")
    py_enc_size = os.path.getsize(py_encrypted)
    print(f"✅ Encrypted file created ({py_enc_size:,} bytes)")

    print_step("1.2", "Decrypt with Rust")
    run_command(f"{RUST_BINARY} --decrypt {py_encrypted} --output {py_decrypted_by_rust} --private-key {priv_key}")
    verify_hash(py_decrypted_by_rust, original_hash, "Rust decrypted Python-encrypted file correctly")

    # ========================================================================
    # TEST 2: Rust Encrypts → Python Decrypts
    # ========================================================================
    print_section("Test 2: Rust Encrypt → Python Decrypt")

    print_step("2.1", "Encrypt with Rust")
    run_command(f"{RUST_BINARY} --encrypt {original_file} --output {rust_encrypted} --public-key {pub_key}")
    rust_enc_size = os.path.getsize(rust_encrypted)
    print(f"✅ Encrypted file created ({rust_enc_size:,} bytes)")

    print_step("2.2", "Decrypt with Python")
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --decrypt {rust_encrypted} --output {rust_decrypted_by_python} --private-key {priv_key}")
    verify_hash(rust_decrypted_by_python, original_hash, "Python decrypted Rust-encrypted file correctly")

    # ========================================================================
    # TEST 3: Self-Decryption Verification
    # ========================================================================
    print_section("Test 3: Self-Decryption Verification")

    print_step("3.1", "Python decrypts its own encrypted file")
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --decrypt {py_encrypted} --output {py_self_decrypted} --private-key {priv_key}")
    verify_hash(py_self_decrypted, original_hash, "Python self-decryption works")

    print_step("3.2", "Rust decrypts its own encrypted file")
    run_command(f"{RUST_BINARY} --decrypt {rust_encrypted} --output {rust_self_decrypted} --private-key {priv_key}")
    verify_hash(rust_self_decrypted, original_hash, "Rust self-decryption works")

    # ========================================================================
    # TEST 4: Encrypted File Format Validation
    # ========================================================================
    print_section("Test 4: Encrypted File Format Validation")

    print_step("4.1", "Verify encrypted files differ (different nonces/salts)")
    py_enc_hash = calculate_hash(py_encrypted)
    rust_enc_hash = calculate_hash(rust_encrypted)

    if py_enc_hash != rust_enc_hash:
        print("✅ SUCCESS: Encrypted files differ (expected due to random nonces/salts)")
        print(f"   Python encrypted hash: {py_enc_hash[:32]}...")
        print(f"   Rust encrypted hash:   {rust_enc_hash[:32]}...")
    else:
        print("❌ FAILURE: Encrypted files are identical (should differ!)")
        sys.exit(1)

    print_step("4.2", "Verify file sizes are comparable")
    size_diff = abs(py_enc_size - rust_enc_size)
    # Encrypted size should be original + header + tags, should be very similar
    if size_diff < 100:  # Allow small variation
        print(f"✅ SUCCESS: File sizes are comparable")
        print(f"   Python: {py_enc_size:,} bytes")
        print(f"   Rust:   {rust_enc_size:,} bytes")
        print(f"   Diff:   {size_diff} bytes")
    else:
        print(f"❌ WARNING: Large size difference: {size_diff} bytes")

    # ========================================================================
    # TEST 5: Security - Truncation Attacks
    # ========================================================================
    print_section("Test 5: Security - Truncation Attack Detection")

    print_step("5.1", "Truncate Python-encrypted file")
    truncated_py = f"{TEST_DIR}/truncated_python.enc"
    with open(py_encrypted, 'rb') as src:
        data = src.read()
    with open(truncated_py, 'wb') as dst:
        dst.write(data[:-100])  # Remove last 100 bytes

    print("Attempting to decrypt with Rust (should fail)...")
    result = subprocess.run(
        f"{RUST_BINARY} --decrypt {truncated_py} --output {TEST_DIR}/tmp.dat --private-key {priv_key}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        print("✅ SUCCESS: Rust detected truncation attack on Python-encrypted file")
    else:
        print("❌ FAILURE: Rust did not detect truncation attack!")
        sys.exit(1)

    print_step("5.2", "Truncate Rust-encrypted file")
    truncated_rust = f"{TEST_DIR}/truncated_rust.enc"
    with open(rust_encrypted, 'rb') as src:
        data = src.read()
    with open(truncated_rust, 'wb') as dst:
        dst.write(data[:-100])  # Remove last 100 bytes

    print("Attempting to decrypt with Python (should fail)...")
    result = subprocess.run(
        f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --decrypt {truncated_rust} --output {TEST_DIR}/tmp.dat --private-key {priv_key}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        print("✅ SUCCESS: Python detected truncation attack on Rust-encrypted file")
    else:
        print("❌ FAILURE: Python did not detect truncation attack!")
        sys.exit(1)

    # ========================================================================
    # TEST 6: Security - Wrong Key Detection
    # ========================================================================
    print_section("Test 6: Security - Wrong Key Detection")

    print_step("6.1", "Generate different keypair")
    wrong_pub = f"{TEST_DIR}/wrong_pub.key"
    wrong_priv = f"{TEST_DIR}/wrong_priv.key"
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --generate-keys --public-key {wrong_pub} --private-key {wrong_priv}")

    print_step("6.2", "Try to decrypt Python-encrypted file with wrong key (Rust)")
    result = subprocess.run(
        f"{RUST_BINARY} --decrypt {py_encrypted} --output {TEST_DIR}/tmp.dat --private-key {wrong_priv}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        print("✅ SUCCESS: Rust detected wrong key for Python-encrypted file")
    else:
        print("❌ FAILURE: Rust accepted wrong key!")
        sys.exit(1)

    print_step("6.3", "Try to decrypt Rust-encrypted file with wrong key (Python)")
    result = subprocess.run(
        f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --decrypt {rust_encrypted} --output {TEST_DIR}/tmp.dat --private-key {wrong_priv}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        print("✅ SUCCESS: Python detected wrong key for Rust-encrypted file")
    else:
        print("❌ FAILURE: Python accepted wrong key!")
        sys.exit(1)

    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    print_section("Test Summary")
    print("""
✅ All interoperability tests passed!

Verified:
  • Python can encrypt, Rust can decrypt
  • Rust can encrypt, Python can decrypt
  • Both implementations can decrypt their own files
  • Encrypted files use proper randomness (differ each time)
  • Truncation attacks are detected by both implementations
  • Wrong keys are rejected by both implementations

The file format is fully compatible in both directions.
""")

if __name__ == "__main__":
    main()
