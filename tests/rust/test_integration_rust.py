import os
import hashlib
import subprocess
import sys
import shutil

# Path to the compiled Rust binary
RUST_BINARY = "./pqenc_rust/target/release/pqenc"
PYTHON_SCRIPT = "./pqenc.py"
PYTHON_INTERPRETER = "/opt/.venv/bin/python3"

def run_command(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed with code {result.returncode}")
        print("Stdout:", result.stdout)
        print("Stderr:", result.stderr)
        sys.exit(1)
    return result

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def main():
    # Setup
    if os.path.exists("test_data_rust"):
        shutil.rmtree("test_data_rust")
    os.makedirs("test_data_rust")
    
    pub_key = "test_data_rust/pub.key"
    priv_key = "test_data_rust/priv.key"
    original_file = "test_data_rust/original.dat"
    encrypted_file = "test_data_rust/encrypted.enc"
    decrypted_file = "test_data_rust/decrypted.dat"
    
    print("=== Rust Implementation Tests ===")
    
    print("\n--- Step 1: Generate Keys (Rust) ---")
    run_command(f"{RUST_BINARY} --generate-keys --public-key {pub_key} --private-key {priv_key}")
    
    print("\n--- Step 2: Create Large File (10MB) ---")
    with open(original_file, 'wb') as f:
        f.write(os.urandom(10 * 1024 * 1024))
    original_hash = calculate_hash(original_file)
    print(f"Original Hash: {original_hash}")
    
    print("\n--- Step 3: Encrypt File (Rust) ---")
    run_command(f"{RUST_BINARY} --encrypt {original_file} --output {encrypted_file} --public-key {pub_key}")
    
    print("\n--- Step 4: Decrypt File (Rust) ---")
    run_command(f"{RUST_BINARY} --decrypt {encrypted_file} --output {decrypted_file} --private-key {priv_key}")
    
    print("\n--- Step 5: Verify Hash ---")
    decrypted_hash = calculate_hash(decrypted_file)
    if original_hash == decrypted_hash:
        print("SUCCESS: Hashes match!")
    else:
        print("FAILURE: Hashes do not match!")
        sys.exit(1)

    print("\n=== Interoperability Tests ===")
    
    py_encrypted = "test_data_rust/py_encrypted.enc"
    py_decrypted = "test_data_rust/py_decrypted.dat"
    rust_decrypted_from_py = "test_data_rust/rust_decrypted_from_py.dat"
    
    print("\n--- Step 6: Python Encrypt -> Rust Decrypt ---")
    # Encrypt with Python using Rust-generated keys
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --encrypt {original_file} --output {py_encrypted} --public-key {pub_key}")
    
    # Decrypt with Rust
    run_command(f"{RUST_BINARY} --decrypt {py_encrypted} --output {rust_decrypted_from_py} --private-key {priv_key}")
    
    if calculate_hash(rust_decrypted_from_py) == original_hash:
        print("SUCCESS: Rust successfully decrypted Python-encrypted file!")
    else:
        print("FAILURE: Rust failed to decrypt Python-encrypted file!")
        sys.exit(1)
        
    print("\n--- Step 7: Rust Encrypt -> Python Decrypt ---")
    # We already have Rust encrypted file from Step 3
    
    # Decrypt with Python
    run_command(f"{PYTHON_INTERPRETER} {PYTHON_SCRIPT} --decrypt {encrypted_file} --output {py_decrypted} --private-key {priv_key}")
    
    if calculate_hash(py_decrypted) == original_hash:
        print("SUCCESS: Python successfully decrypted Rust-encrypted file!")
    else:
        print("FAILURE: Python failed to decrypt Rust-encrypted file!")
        sys.exit(1)

    print("\n=== Security Tests ===")
    
    print("\n--- Step 8: Truncation Attack (Rust) ---")
    file_size = os.path.getsize(encrypted_file)
    with open(encrypted_file, 'rb+') as f:
        f.truncate(file_size - 100)
        
    print("Attempting to decrypt truncated file (should fail)...")
    result = subprocess.run(f"{RUST_BINARY} --decrypt {encrypted_file} --output {decrypted_file} --private-key {priv_key}",
                            shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("SUCCESS: Decryption failed as expected.")
    else:
        print("FAILURE: Decryption succeeded on truncated file!")
        sys.exit(1)

if __name__ == "__main__":
    main()
