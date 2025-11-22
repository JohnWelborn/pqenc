import os
import hashlib
import subprocess
import sys

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
    if os.path.exists("test_data"):
        import shutil
        shutil.rmtree("test_data")
    os.makedirs("test_data")
    
    pub_key = "test_data/pub.key"
    priv_key = "test_data/priv.key"
    original_file = "test_data/original.dat"
    encrypted_file = "test_data/encrypted.enc"
    decrypted_file = "test_data/decrypted.dat"
    
    print("--- Step 1: Generate Keys ---")
    run_command(f"/opt/.venv/bin/python3 pqenc.py --generate-keys --public-key {pub_key} --private-key {priv_key}")
    
    print("\n--- Step 2: Create Large File (10MB) ---")
    with open(original_file, 'wb') as f:
        f.write(os.urandom(10 * 1024 * 1024))
    original_hash = calculate_hash(original_file)
    print(f"Original Hash: {original_hash}")
    
    print("\n--- Step 3: Encrypt File ---")
    run_command(f"/opt/.venv/bin/python3 pqenc.py --encrypt {original_file} --output {encrypted_file} --public-key {pub_key}")
    
    print("\n--- Step 4: Decrypt File ---")
    run_command(f"/opt/.venv/bin/python3 pqenc.py --decrypt {encrypted_file} --output {decrypted_file} --private-key {priv_key}")
    
    print("\n--- Step 5: Verify Hash ---")
    decrypted_hash = calculate_hash(decrypted_file)
    print(f"Decrypted Hash: {decrypted_hash}")
    
    if original_hash == decrypted_hash:
        print("SUCCESS: Hashes match!")
    else:
        print("FAILURE: Hashes do not match!")
        sys.exit(1)

    print("\n--- Step 6: Truncation Attack Test ---")
    # Truncate the encrypted file by 100 bytes
    file_size = os.path.getsize(encrypted_file)
    with open(encrypted_file, 'rb+') as f:
        f.truncate(file_size - 100)
    
    print("Attempting to decrypt truncated file (should fail)...")
    result = subprocess.run(f"/opt/.venv/bin/python3 pqenc.py --decrypt {encrypted_file} --output {decrypted_file} --private-key {priv_key}",
                            shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("SUCCESS: Decryption failed as expected.")
    else:
        print("FAILURE: Decryption succeeded on truncated file!")
        sys.exit(1)

if __name__ == "__main__":
    main()
