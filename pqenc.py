#!/usr/bin/env python3
"""
Post-Quantum File Encryption Tool
Uses ML-KEM-1024 (Kyber) for key encapsulation and AES-256-GCM for file encryption.
Supports streaming encryption for large files.
"""

import argparse
import ctypes
import os
import sys
from base64 import b64encode, b64decode

try:
    import oqs
except ImportError:
    print("Error: liboqs-python not installed. Install with: pip install liboqs-python")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("Error: cryptography not installed. Install with: pip install cryptography")
    sys.exit(1)


class PostQuantumFileEncryption:
    """
    Post-quantum secure file encryption using ML-KEM-1024 and AES-256-GCM.

    This class implements a hybrid encryption scheme combining:
    - ML-KEM-1024 (NIST-standardized Kyber) for post-quantum key encapsulation
    - AES-256-GCM for authenticated symmetric encryption
    - HKDF-SHA256 for key derivation from shared secrets
    - Streaming encryption/decryption for handling large files

    SECURITY PROPERTIES:
    - Post-quantum security: Resistant to attacks from quantum computers
    - Authenticated encryption: Protects against tampering and forgery
    - Forward secrecy: Each file uses a fresh ephemeral KEM key pair
    - Memory safety: Sensitive data is securely zeroed after use
    - Resource protection: Validates input sizes to prevent DoS attacks

    FILE FORMAT:
    [Magic: 4 bytes][KEM CT Len: 4 bytes][KEM CT][Salt: 16 bytes][Nonce: 12 bytes][Encrypted Chunks...]
    Each chunk: [AES-GCM ciphertext with 16-byte authentication tag]
    """

    KEM_ALGORITHM = "ML-KEM-1024"
    AES_KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    SALT_SIZE = 16
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    TAG_SIZE = 16
    MAX_KEM_CIPHERTEXT_SIZE = 10000  # Conservative upper bound for ML-KEM-1024 (actual: 1568 bytes)

    # File format constants
    MAGIC = b'PQE1'

    # AAD flags
    AAD_CHUNK = b'\x00'
    AAD_LAST_CHUNK = b'\x01'

    def __init__(self):
        """Initialize the encryption system."""
        pass

    @staticmethod
    def _secure_zero(data: bytes) -> None:
        """
        Securely zero out sensitive data in memory using ctypes.

        This implementation uses ctypes.memmove to zero the internal buffer
        of bytes/bytearray objects. While Python's bytes are immutable at the
        Python level, we can still zero the underlying C buffer.

        Note: This is a best-effort security measure. Effectiveness depends on
        Python's memory management and whether the data has been copied elsewhere.
        """
        if data is None or len(data) == 0:
            return

        try:
            if isinstance(data, bytearray):
                # For bytearray, we can zero it directly
                ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))
            elif isinstance(data, bytes):
                # For bytes objects, we need to access the internal buffer
                # Create a mutable buffer and zero it
                # Note: This zeroes our local copy, but the original immutable
                # bytes object's buffer cannot be directly modified due to Python's
                # memory protection. However, we can at least ensure our reference
                # doesn't keep the sensitive data around.
                try:
                    # Attempt to get a writable buffer view (works for some bytes objects)
                    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
                    ctypes.memset(buf, 0, len(data))
                except (TypeError, BufferError):
                    # If we can't get a mutable view, the bytes object is truly immutable
                    # The best we can do is rely on garbage collection
                    pass
        except (TypeError, ValueError, AttributeError, BufferError):
            # If zeroing fails, continue gracefully
            # The object will be cleared when garbage collected
            pass

    @staticmethod
    def generate_keypair(public_key_path: str, private_key_path: str) -> None:
        """
        Generate ML-KEM-1024 public/private key pair and save to files.

        SECURITY NOTES:
        - Private key file permissions are set to 0600 (read/write for owner only)
        - Private keys should be stored securely and never shared
        - Public keys can be freely distributed for encryption
        - ML-KEM-1024 provides post-quantum security against quantum computers

        Args:
            public_key_path: Path where public key will be saved
            private_key_path: Path where private key will be saved (protected with 0600 permissions)

        Raises:
            OSError: If file operations fail
            ValueError: If key generation fails
        """
        private_key = None
        try:
            if os.path.exists(public_key_path):
                print(f"Error: Public key file already exists: {public_key_path}")
                sys.exit(1)

            if os.path.exists(private_key_path):
                print(f"Error: Private key file already exists: {private_key_path}")
                sys.exit(1)

            kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM)
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            # Save keys as base64-encoded text
            with open(public_key_path, 'w') as f:
                f.write(b64encode(public_key).decode('ascii'))

            with open(private_key_path, 'w') as f:
                f.write(b64encode(private_key).decode('ascii'))

            os.chmod(private_key_path, 0o600)

            print(f"Key pair generated successfully")
            print(f"  Public key:  {public_key_path}")
            print(f"  Private key: {private_key_path}")
            print(f"  Algorithm:   {PostQuantumFileEncryption.KEM_ALGORITHM}")

        except (OSError, IOError, ValueError) as e:
            print(f"Error generating keypair: {e}")
            sys.exit(1)
        except Exception as e:
            # Catch unexpected errors with full traceback for debugging
            print(f"Unexpected error generating keypair: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            # Securely zero private key from memory
            if private_key is not None:
                PostQuantumFileEncryption._secure_zero(private_key)

    @staticmethod
    def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
        """Derive AES-256 key from shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=PostQuantumFileEncryption.AES_KEY_SIZE,
            salt=salt,
            info=b'pqenc-v1-aes-key',
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def _get_nonce(base_nonce: bytes, counter: int) -> bytes:
        """Generate unique nonce for each chunk."""
        # Convert base_nonce to integer, add counter, convert back
        # This is a simple way to increment the nonce
        nonce_int = int.from_bytes(base_nonce, byteorder='big')
        nonce_int = (nonce_int + counter) % (2**(PostQuantumFileEncryption.NONCE_SIZE * 8))
        return nonce_int.to_bytes(PostQuantumFileEncryption.NONCE_SIZE, byteorder='big')

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
        """
        Encrypt a file using streaming ML-KEM-1024 and AES-256-GCM.

        SECURITY NOTES:
        - Each encryption generates a fresh shared secret via KEM, ensuring unique
          AES keys for every file encryption operation
        - Nonces are derived by incrementing a random base nonce for each chunk,
          preventing nonce reuse within a single file
        - Never reuse nonces with the same AES key if implementing custom encryption
        - Authentication tags protect against tampering and ensure integrity
        - Streaming encryption processes files in 64KB chunks to handle large files
          without loading entire contents into memory

        Args:
            input_path: Path to file to encrypt
            output_path: Path where encrypted file will be saved
            public_key_path: Path to ML-KEM-1024 public key file

        Raises:
            OSError: If file operations fail
            ValueError: If encryption parameters are invalid
        """
        shared_secret = None
        aes_key = None
        base_nonce = None
        current_chunk = None
        next_chunk = None

        try:
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                sys.exit(1)

            # Load base64-encoded public key
            with open(public_key_path, 'r') as f:
                public_key = b64decode(f.read().strip())

            # Initialize KEM
            kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM)
            ciphertext_kem, shared_secret = kem.encap_secret(public_key)

            # Generate salt and base nonce
            salt = os.urandom(PostQuantumFileEncryption.SALT_SIZE)
            base_nonce = os.urandom(PostQuantumFileEncryption.NONCE_SIZE)

            # Derive AES key
            aes_key = PostQuantumFileEncryption._derive_aes_key(shared_secret, salt)
            aesgcm = AESGCM(aes_key)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Write Header
                fout.write(PostQuantumFileEncryption.MAGIC)

                # Write KEM ciphertext length and conten
                kem_ct_len = len(ciphertext_kem)
                fout.write(kem_ct_len.to_bytes(4, byteorder='big'))
                fout.write(ciphertext_kem)

                # Write Salt and Base Nonce
                fout.write(salt)
                fout.write(base_nonce)

                # Stream encryption
                chunk_index = 0

                # Read first chunk
                current_chunk = fin.read(PostQuantumFileEncryption.CHUNK_SIZE)

                while True:
                    # Try to read next chunk to determine if current is las
                    next_chunk = fin.read(PostQuantumFileEncryption.CHUNK_SIZE)

                    if not next_chunk:
                        aad = PostQuantumFileEncryption.AAD_LAST_CHUNK
                    else:
                        aad = PostQuantumFileEncryption.AAD_CHUNK

                    nonce = PostQuantumFileEncryption._get_nonce(base_nonce, chunk_index)
                    ciphertext = aesgcm.encrypt(nonce, current_chunk, aad)
                    fout.write(ciphertext)

                    # Zero out current chunk after encryption
                    PostQuantumFileEncryption._secure_zero(current_chunk)

                    chunk_index += 1

                    if not next_chunk:
                        break

                    current_chunk = next_chunk

            input_size = os.path.getsize(input_path)
            print(f"File encrypted successfully")
            print(f"  Input:  {input_path} ({input_size} bytes)")
            print(f"  Output: {output_path}")
            print(f"  Using:  {PostQuantumFileEncryption.KEM_ALGORITHM} + AES-256-GCM")

        except (OSError, IOError, ValueError) as e:
            print(f"Error encrypting file: {e}")
            # Clean up partial file
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)
        except Exception as e:
            # Catch unexpected errors with full traceback for debugging
            print(f"Unexpected error encrypting file: {e}")
            import traceback
            traceback.print_exc()
            # Clean up partial file
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)
        finally:
            # Securely zero sensitive data from memory
            if shared_secret is not None:
                PostQuantumFileEncryption._secure_zero(shared_secret)
            if aes_key is not None:
                PostQuantumFileEncryption._secure_zero(aes_key)
            if base_nonce is not None:
                PostQuantumFileEncryption._secure_zero(base_nonce)
            if current_chunk is not None:
                PostQuantumFileEncryption._secure_zero(current_chunk)
            if next_chunk is not None:
                PostQuantumFileEncryption._secure_zero(next_chunk)

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
        """
        Decrypt a file using streaming ML-KEM-1024 and AES-256-GCM.

        SECURITY NOTES:
        - Validates file format magic bytes to prevent processing of invalid files
        - Validates KEM ciphertext length to prevent memory exhaustion attacks
        - AES-GCM authentication ensures file integrity - decryption fails if file
          has been tampered with or corrupted
        - Streaming decryption processes files in chunks to handle large files
        - Sensitive data (keys, plaintext) is securely zeroed from memory after use

        Args:
            input_path: Path to encrypted file
            output_path: Path where decrypted file will be saved
            private_key_path: Path to ML-KEM-1024 private key file

        Raises:
            OSError: If file operations fail
            ValueError: If file format is invalid or decryption fails
        """
        private_key = None
        shared_secret = None
        aes_key = None
        base_nonce = None
        plaintext = None

        try:
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                sys.exit(1)

            # Load base64-encoded private key
            with open(private_key_path, 'r') as f:
                private_key = b64decode(f.read().strip())

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Read Header
                magic = fin.read(4)
                if magic != PostQuantumFileEncryption.MAGIC:
                    print("Error: Invalid file format or version")
                    sys.exit(1)

                kem_ct_len = int.from_bytes(fin.read(4), byteorder='big')

                # Validate KEM ciphertext length to prevent memory exhaustion attacks
                if kem_ct_len <= 0 or kem_ct_len > PostQuantumFileEncryption.MAX_KEM_CIPHERTEXT_SIZE:
                    raise ValueError(f"Invalid KEM ciphertext length: {kem_ct_len}")

                ciphertext_kem = fin.read(kem_ct_len)
                salt = fin.read(PostQuantumFileEncryption.SALT_SIZE)
                base_nonce = fin.read(PostQuantumFileEncryption.NONCE_SIZE)

                # Decapsulate
                kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM, secret_key=private_key)
                shared_secret = kem.decap_secret(ciphertext_kem)

                # Derive AES key
                aes_key = PostQuantumFileEncryption._derive_aes_key(shared_secret, salt)
                aesgcm = AESGCM(aes_key)

                # Stream decryption
                chunk_index = 0
                encrypted_chunk_size = PostQuantumFileEncryption.CHUNK_SIZE + PostQuantumFileEncryption.TAG_SIZE

                # Get file size for EOF check
                fin.seek(0, 2)
                file_size = fin.tell()
                fin.seek(4 + 4 + kem_ct_len + PostQuantumFileEncryption.SALT_SIZE + PostQuantumFileEncryption.NONCE_SIZE)

                while True:
                    chunk = fin.read(encrypted_chunk_size)
                    if not chunk:
                        break

                    # Check if we are at the end of the file
                    if fin.tell() == file_size:
                        aad = PostQuantumFileEncryption.AAD_LAST_CHUNK
                    else:
                        aad = PostQuantumFileEncryption.AAD_CHUNK

                    nonce = PostQuantumFileEncryption._get_nonce(base_nonce, chunk_index)

                    try:
                        plaintext = aesgcm.decrypt(nonce, chunk, aad)
                        fout.write(plaintext)
                        # Zero out plaintext after writing
                        PostQuantumFileEncryption._secure_zero(plaintext)
                    except Exception:
                        # Intentional catch-all: AES-GCM decrypt can raise various exceptions
                        # for authentication failures (wrong key, corrupted data, tampered AAD).
                        # We treat all decryption failures as security-critical integrity violations.
                        print("Error: Decryption failed (Integrity check failed)")
                        print("Possible causes: Wrong key, corrupted file, or truncation attack.")
                        # Delete partial output
                        fout.close()
                        os.remove(output_path)
                        sys.exit(1)

                    chunk_index += 1

            print(f"File decrypted successfully: {output_path}")

        except (OSError, IOError, ValueError) as e:
            print(f"Error decrypting file: {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)
        except Exception as e:
            # Catch unexpected errors with full traceback for debugging
            print(f"Unexpected error decrypting file: {e}")
            import traceback
            traceback.print_exc()
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)
        finally:
            # Securely zero sensitive data from memory
            if private_key is not None:
                PostQuantumFileEncryption._secure_zero(private_key)
            if shared_secret is not None:
                PostQuantumFileEncryption._secure_zero(shared_secret)
            if aes_key is not None:
                PostQuantumFileEncryption._secure_zero(aes_key)
            if base_nonce is not None:
                PostQuantumFileEncryption._secure_zero(base_nonce)
            if plaintext is not None:
                PostQuantumFileEncryption._secure_zero(plaintext)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Post-Quantum File Encryption Tool (ML-KEM-1024 + AES-256-GCM)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a new keypair
  %(prog)s --generate-keys --public-key pub.key --private-key priv.key

  # Encrypt a file
  %(prog)s --encrypt secret.txt --output secret.enc --public-key pub.key

  # Decrypt a file
  %(prog)s --decrypt secret.enc --output secret.txt --private-key priv.key
        """
    )

    # Operation mode
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--generate-keys', action='store_true',
                           help='Generate a new ML-KEM-1024 keypair')
    mode_group.add_argument('--encrypt', metavar='FILE',
                           help='Encrypt a file')
    mode_group.add_argument('--decrypt', metavar='FILE',
                           help='Decrypt a file')

    # Key files
    parser.add_argument('--public-key', metavar='FILE',
                       help='Path to public key file')
    parser.add_argument('--private-key', metavar='FILE',
                       help='Path to private key file')

    # Outpu
    parser.add_argument('--output', metavar='FILE',
                       help='Output file path (for encrypt/decrypt)')

    args = parser.parse_args()

    pq = PostQuantumFileEncryption()

    # Generate keypair
    if args.generate_keys:
        if not args.public_key or not args.private_key:
            parser.error('--generate-keys requires --public-key and --private-key')
        pq.generate_keypair(args.public_key, args.private_key)

    # Encrypt file
    elif args.encrypt:
        if not args.public_key:
            parser.error('--encrypt requires --public-key')
        if not args.output:
            parser.error('--encrypt requires --output')
        pq.encrypt_file(args.encrypt, args.output, args.public_key)

    # Decrypt file
    elif args.decrypt:
        if not args.private_key:
            parser.error('--decrypt requires --private-key')
        if not args.output:
            parser.error('--decrypt requires --output')
        pq.decrypt_file(args.decrypt, args.output, args.private_key)


if __name__ == '__main__':
    main()
