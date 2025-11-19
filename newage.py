#!/usr/bin/env python3
"""
Post-Quantum File Encryption Tool
Uses ML-KEM-1024 (Kyber) for key encapsulation and AES-256-GCM for file encryption.
Supports streaming encryption for large files.
"""

import argparse
import os
import sys

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
    """Post-quantum secure file encryption using ML-KEM-1024 and AES-256-GCM."""

    KEM_ALGORITHM = "ML-KEM-1024"
    AES_KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    SALT_SIZE = 16
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    TAG_SIZE = 16

    # File format constants
    MAGIC = b'NAv1'

    # AAD flags
    AAD_CHUNK = b'\x00'
    AAD_LAST_CHUNK = b'\x01'

    def __init__(self):
        """Initialize the encryption system."""
        pass

    @staticmethod
    def generate_keypair(public_key_path: str, private_key_path: str) -> None:
        """
        Generate ML-KEM-1024 public/private key pair and save to files.
        """
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

            with open(public_key_path, 'wb') as f:
                f.write(public_key)

            with open(private_key_path, 'wb') as f:
                f.write(private_key)

            os.chmod(private_key_path, 0o600)

            print(f"Key pair generated successfully")
            print(f"  Public key:  {public_key_path}")
            print(f"  Private key: {private_key_path}")
            print(f"  Algorithm:   {PostQuantumFileEncryption.KEM_ALGORITHM}")

        except Exception as e:
            print(f"Error generating keypair: {e}")
            sys.exit(1)

    @staticmethod
    def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
        """Derive AES-256 key from shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=PostQuantumFileEncryption.AES_KEY_SIZE,
            salt=salt,
            info=b'newage-v2-aes-key',
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
        """Encrypt a file using streaming ML-KEM-1024 and AES-256-GCM."""
        try:
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                sys.exit(1)

            with open(public_key_path, 'rb') as f:
                public_key = f.read()

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

                    chunk_index += 1

                    if not next_chunk:
                        break

                    current_chunk = next_chunk

            input_size = os.path.getsize(input_path)
            print(f"File encrypted successfully")
            print(f"  Input:  {input_path} ({input_size} bytes)")
            print(f"  Output: {output_path}")
            print(f"  Using:  {PostQuantumFileEncryption.KEM_ALGORITHM} + AES-256-GCM")

        except Exception as e:
            print(f"Error encrypting file: {e}")
            # Clean up partial file
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
        """Decrypt a file using streaming ML-KEM-1024 and AES-256-GCM."""
        try:
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                sys.exit(1)

            with open(private_key_path, 'rb') as f:
                private_key = f.read()

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Read Header
                magic = fin.read(4)
                if magic != PostQuantumFileEncryption.MAGIC:
                    print("Error: Invalid file format or version")
                    sys.exit(1)

                kem_ct_len = int.from_bytes(fin.read(4), byteorder='big')
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
                    except Exception:
                        print("Error: Decryption failed (Integrity check failed)")
                        print("Possible causes: Wrong key, corrupted file, or truncation attack.")
                        # Delete partial outpu
                        fout.close()
                        os.remove(output_path)
                        sys.exit(1)

                    chunk_index += 1

            print(f"File decrypted successfully: {output_path}")

        except Exception as e:
            print(f"Error decrypting file: {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)


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
