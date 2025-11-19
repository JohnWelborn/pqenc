#!/usr/bin/env python3
"""
Unit tests for Post-Quantum File Encryption Tool
"""

import os
import tempfile
import unittest
from pathlib import Path

from pqenc import PostQuantumFileEncryption


class TestPostQuantumFileEncryption(unittest.TestCase):
    """Test suite for post-quantum file encryption."""

    def setUp(self):
        """Set up temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.public_key_path = os.path.join(self.test_dir, "test_pub.key")
        self.private_key_path = os.path.join(self.test_dir, "test_priv.key")
        self.plaintext_path = os.path.join(self.test_dir, "test_plain.txt")
        self.encrypted_path = os.path.join(self.test_dir, "test_encrypted.enc")
        self.decrypted_path = os.path.join(self.test_dir, "test_decrypted.txt")

    def tearDown(self):
        """Clean up temporary files after tests."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_generate_keypair(self):
        """Test keypair generation creates both public and private keys."""
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Verify both key files exist
        self.assertTrue(os.path.exists(self.public_key_path))
        self.assertTrue(os.path.exists(self.private_key_path))

        # Verify keys are not empty
        self.assertGreater(os.path.getsize(self.public_key_path), 0)
        self.assertGreater(os.path.getsize(self.private_key_path), 0)

        # Verify private key has restrictive permissions (Unix-like systems)
        if hasattr(os, 'chmod'):
            stat_info = os.stat(self.private_key_path)
            permissions = stat_info.st_mode & 0o777
            self.assertEqual(permissions, 0o600)

    def test_keys_are_base64_encoded(self):
        """Test that generated keys are stored as valid base64-encoded text."""
        from base64 import b64decode

        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Read public key
        with open(self.public_key_path, 'r') as f:
            public_key_text = f.read()

        # Read private key
        with open(self.private_key_path, 'r') as f:
            private_key_text = f.read()

        # Verify keys are text (ASCII/UTF-8), not binary
        self.assertIsInstance(public_key_text, str)
        self.assertIsInstance(private_key_text, str)

        # Verify keys contain only base64 characters (A-Z, a-z, 0-9, +, /, =)
        import re
        base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
        self.assertTrue(base64_pattern.match(public_key_text.strip()),
                        "Public key should contain only base64 characters")
        self.assertTrue(base64_pattern.match(private_key_text.strip()),
                        "Private key should contain only base64 characters")

        # Verify keys can be decoded from base64 without errors
        try:
            public_key_bytes = b64decode(public_key_text)
            private_key_bytes = b64decode(private_key_text)
        except Exception as e:
            self.fail(f"Failed to decode keys from base64: {e}")

        # Verify decoded keys are not empty and have reasonable sizes
        # ML-KEM-1024 public key should be 1568 bytes, private key should be 3168 bytes
        self.assertGreater(len(public_key_bytes), 1000, "Decoded public key too small")
        self.assertGreater(len(private_key_bytes), 2000, "Decoded private key too small")
        self.assertLess(len(public_key_bytes), 5000, "Decoded public key too large")
        self.assertLess(len(private_key_bytes), 10000, "Decoded private key too large")

    def test_generate_keypair_refuse_overwrite_public(self):
        """Test that generate_keypair refuses to overwrite existing public key."""
        # Create initial keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Try to generate again - should fail
        new_private = os.path.join(self.test_dir, "new_priv.key")
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.generate_keypair(
                self.public_key_path,  # This already exists
                new_private
            )

    def test_generate_keypair_refuse_overwrite_private(self):
        """Test that generate_keypair refuses to overwrite existing private key."""
        # Create initial keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Try to generate again - should fail
        new_public = os.path.join(self.test_dir, "new_pub.key")
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.generate_keypair(
                new_public,
                self.private_key_path  # This already exists
            )

    def test_encrypt_decrypt_simple_text(self):
        """Test encrypting and decrypting a simple text file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test plaintext file
        test_data = b"Hello, Post-Quantum World!"
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Verify encrypted file exists and is different from plaintext
        self.assertTrue(os.path.exists(self.encrypted_path))
        with open(self.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        self.assertNotEqual(encrypted_data, test_data)

        # Decrypt the file
        PostQuantumFileEncryption.decrypt_file(
            self.encrypted_path,
            self.decrypted_path,
            self.private_key_path
        )

        # Verify decrypted file matches original
        with open(self.decrypted_path, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, test_data)

    def test_encrypt_decrypt_large_file(self):
        """Test encrypting and decrypting a large file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test file with 1MB of data
        test_data = os.urandom(1024 * 1024)  # 1MB random data
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Decrypt the file
        PostQuantumFileEncryption.decrypt_file(
            self.encrypted_path,
            self.decrypted_path,
            self.private_key_path
        )

        # Verify decrypted file matches original
        with open(self.decrypted_path, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, test_data)

    def test_encrypt_decrypt_empty_file(self):
        """Test encrypting and decrypting an empty file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create empty file
        with open(self.plaintext_path, 'wb') as f:
            pass

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Decrypt the file
        PostQuantumFileEncryption.decrypt_file(
            self.encrypted_path,
            self.decrypted_path,
            self.private_key_path
        )

        # Verify decrypted file is empty
        self.assertEqual(os.path.getsize(self.decrypted_path), 0)

    def test_encrypt_decrypt_binary_data(self):
        """Test encrypting and decrypting binary data."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test file with various binary data including null bytes
        test_data = bytes(range(256)) * 100  # All byte values repeated
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Decrypt the file
        PostQuantumFileEncryption.decrypt_file(
            self.encrypted_path,
            self.decrypted_path,
            self.private_key_path
        )

        # Verify decrypted file matches original
        with open(self.decrypted_path, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, test_data)

    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong private key."""
        # Generate first keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create and encrypt a file
        test_data = b"Secret message"
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Generate a different keypair
        wrong_private_key = os.path.join(self.test_dir, "wrong_priv.key")
        wrong_public_key = os.path.join(self.test_dir, "wrong_pub.key")
        PostQuantumFileEncryption.generate_keypair(
            wrong_public_key,
            wrong_private_key
        )

        # Try to decrypt with wrong private key - should fail
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                self.encrypted_path,
                self.decrypted_path,
                wrong_private_key
            )

    def test_encrypt_refuse_overwrite(self):
        """Test that encrypt refuses to overwrite existing output file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test plaintext
        with open(self.plaintext_path, 'wb') as f:
            f.write(b"test data")

        # Encrypt once
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Try to encrypt again to same output - should fail
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.encrypt_file(
                self.plaintext_path,
                self.encrypted_path,
                self.public_key_path
            )

    def test_decrypt_refuse_overwrite(self):
        """Test that decrypt refuses to overwrite existing output file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create and encrypt test file
        with open(self.plaintext_path, 'wb') as f:
            f.write(b"test data")

        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Create a file at the decrypted path
        with open(self.decrypted_path, 'wb') as f:
            f.write(b"existing file")

        # Try to decrypt - should fail because output exists
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                self.encrypted_path,
                self.decrypted_path,
                self.private_key_path
            )

    def test_encrypt_nonexistent_input(self):
        """Test that encrypt fails gracefully with nonexistent input file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Try to encrypt nonexistent file
        nonexistent = os.path.join(self.test_dir, "nonexistent.txt")
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.encrypt_file(
                nonexistent,
                self.encrypted_path,
                self.public_key_path
            )

    def test_encrypt_nonexistent_public_key(self):
        """Test that encrypt fails gracefully with nonexistent public key."""
        # Create test plaintext
        with open(self.plaintext_path, 'wb') as f:
            f.write(b"test data")

        # Try to encrypt with nonexistent public key
        nonexistent_key = os.path.join(self.test_dir, "nonexistent.key")
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.encrypt_file(
                self.plaintext_path,
                self.encrypted_path,
                nonexistent_key
            )

    def test_decrypt_nonexistent_input(self):
        """Test that decrypt fails gracefully with nonexistent input file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Try to decrypt nonexistent file
        nonexistent = os.path.join(self.test_dir, "nonexistent.enc")
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                nonexistent,
                self.decrypted_path,
                self.private_key_path
            )

    def test_decrypt_corrupted_file(self):
        """Test that decrypt fails gracefully with corrupted encrypted file."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create and encrypt test file
        with open(self.plaintext_path, 'wb') as f:
            f.write(b"test data")

        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Corrupt the encrypted file
        with open(self.encrypted_path, 'r+b') as f:
            f.seek(100)
            f.write(b'\x00' * 50)

        # Try to decrypt corrupted file - should fail
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                self.encrypted_path,
                self.decrypted_path,
                self.private_key_path
            )

    def test_multiple_encryptions_produce_different_ciphertexts(self):
        """Test that encrypting the same file twice produces different ciphertexts."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test plaintext
        test_data = b"Same data encrypted twice"
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt first time
        encrypted_path1 = os.path.join(self.test_dir, "encrypted1.enc")
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            encrypted_path1,
            self.public_key_path
        )

        # Encrypt second time
        encrypted_path2 = os.path.join(self.test_dir, "encrypted2.enc")
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            encrypted_path2,
            self.public_key_path
        )

        # Read both encrypted files
        with open(encrypted_path1, 'rb') as f:
            ciphertext1 = f.read()
        with open(encrypted_path2, 'rb') as f:
            ciphertext2 = f.read()

        # Verify they are different (due to random nonce and KEM encapsulation)
        self.assertNotEqual(ciphertext1, ciphertext2)

        # But both should decrypt to the same plaintext
        decrypted_path1 = os.path.join(self.test_dir, "decrypted1.txt")
        decrypted_path2 = os.path.join(self.test_dir, "decrypted2.txt")

        PostQuantumFileEncryption.decrypt_file(
            encrypted_path1,
            decrypted_path1,
            self.private_key_path
        )
        PostQuantumFileEncryption.decrypt_file(
            encrypted_path2,
            decrypted_path2,
            self.private_key_path
        )

        with open(decrypted_path1, 'rb') as f:
            decrypted1 = f.read()
        with open(decrypted_path2, 'rb') as f:
            decrypted2 = f.read()

        self.assertEqual(decrypted1, test_data)
        self.assertEqual(decrypted2, test_data)


class TestEncryptedFileFormat(unittest.TestCase):
    """Test the encrypted file format structure."""

    def setUp(self):
        """Set up temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.public_key_path = os.path.join(self.test_dir, "test_pub.key")
        self.private_key_path = os.path.join(self.test_dir, "test_priv.key")
        self.plaintext_path = os.path.join(self.test_dir, "test_plain.txt")
        self.encrypted_path = os.path.join(self.test_dir, "test_encrypted.enc")
        self.decrypted_path = os.path.join(self.test_dir, "test_decrypted.txt")

    def tearDown(self):
        """Clean up temporary files after tests."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_encrypted_file_format(self):
        """Test that encrypted file has correct format structure (V1)."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test plaintext
        test_data = b"Test data for format verification"
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Read and verify format
        with open(self.encrypted_path, 'rb') as f:
            # 1. Magic (4 bytes)
            magic = f.read(4)
            self.assertEqual(magic, b'PQE1')

            # 2. KEM ciphertext length (4 bytes)
            kem_ct_len_bytes = f.read(4)
            self.assertEqual(len(kem_ct_len_bytes), 4)
            kem_ct_len = int.from_bytes(kem_ct_len_bytes, byteorder='big')

            # Verify KEM ciphertext length is reasonable for ML-KEM-1024
            self.assertEqual(kem_ct_len, 1568)

            # 3. KEM ciphertext
            kem_ct = f.read(kem_ct_len)
            self.assertEqual(len(kem_ct), kem_ct_len)

            # 4. Salt (16 bytes)
            salt = f.read(16)
            self.assertEqual(len(salt), 16)

            # 5. Base Nonce (12 bytes)
            base_nonce = f.read(12)
            self.assertEqual(len(base_nonce), 12)

            # 6. Chunks
            # Since data is small, there should be one chunk
            # Chunk format: Ciphertext + Tag (16 bytes)
            chunk = f.read()
            expected_chunk_len = len(test_data) + 16
            self.assertEqual(len(chunk), expected_chunk_len)

    def test_truncation_attack(self):
        """Test that decryption fails if the file is truncated."""
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        # Create test plaintext (large enough to potentially have multiple chunks if we lowered chunk size, 
        # but here just ensure it has some data)
        test_data = os.urandom(1000)
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        # Encrypt the file
        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # Truncate the encrypted file by 1 byte (corrupting the tag or missing the last byte)
        file_size = os.path.getsize(self.encrypted_path)
        with open(self.encrypted_path, 'rb+') as f:
            f.truncate(file_size - 1)

        # Try to decrypt - should fail
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                self.encrypted_path,
                self.decrypted_path,
                self.private_key_path
            )

    def test_chunk_reordering_attack(self):
        """Test that swapping chunks fails decryption."""
        # This requires enough data for at least 2 chunks
        # CHUNK_SIZE is 64KB. Let's make 150KB file.
        
        # Generate keypair
        PostQuantumFileEncryption.generate_keypair(
            self.public_key_path,
            self.private_key_path
        )

        data_size = 150 * 1024
        test_data = os.urandom(data_size)
        with open(self.plaintext_path, 'wb') as f:
            f.write(test_data)

        PostQuantumFileEncryption.encrypt_file(
            self.plaintext_path,
            self.encrypted_path,
            self.public_key_path
        )

        # We need to manually manipulate the file to swap chunks.
        # Header size = 4 + 4 + 1568 + 16 + 12 = 1604 bytes
        # Chunk 1 size = 64KB + 16 = 65552 bytes
        # Chunk 2 size = 64KB + 16 = 65552 bytes
        # Chunk 3 size = remainder + 16
        
        header_size = 4 + 4 + 1568 + 16 + 12
        chunk_overhead = 16
        chunk_payload = 64 * 1024
        full_chunk_size = chunk_payload + chunk_overhead
        
        with open(self.encrypted_path, 'rb') as f:
            header = f.read(header_size)
            chunk1 = f.read(full_chunk_size)
            chunk2 = f.read(full_chunk_size)
            rest = f.read()
            
        # Swap chunk 1 and chunk 2
        with open(self.encrypted_path, 'wb') as f:
            f.write(header)
            f.write(chunk2)
            f.write(chunk1)
            f.write(rest)
            
        # Decrypt should fail (tag mismatch because nonce depends on counter)
        with self.assertRaises(SystemExit):
            PostQuantumFileEncryption.decrypt_file(
                self.encrypted_path,
                self.decrypted_path,
                self.private_key_path
            )


if __name__ == '__main__':
    unittest.main()
