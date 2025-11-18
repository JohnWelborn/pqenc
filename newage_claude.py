#!/usr/bin/env python3
"""
Post-Quantum File Encryption Tool
Uses ML-KEM-1024 (Kyber) for key encapsulation and AES-256-GCM for file encryption.
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

    KEM_ALGORITHM = "ML-KEM-1024"  # Post-quantum key encapsulation mechanism
    AES_KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM

    def __init__(self):
        """Initialize the encryption system."""
        pass

    @staticmethod
    def generate_keypair(public_key_path: str, private_key_path: str) -> None:
        """
        Generate ML-KEM-1024 public/private key pair and save to files.

        Args:
            public_key_path: Path where public key will be saved
            private_key_path: Path where private key will be saved
        """
        try:
            # Check if output files already exist
            if os.path.exists(public_key_path):
                print(f"Error: Public key file already exists: {public_key_path}")
                print("Refusing to overwrite. Please remove the file or choose a different path.")
                sys.exit(1)

            if os.path.exists(private_key_path):
                print(f"Error: Private key file already exists: {private_key_path}")
                print("Refusing to overwrite. Please remove the file or choose a different path.")
                sys.exit(1)

            # Initialize KEM with ML-KEM-1024
            kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM)

            # Generate keypair
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            # Save keys to files
            with open(public_key_path, 'wb') as f:
                f.write(public_key)

            with open(private_key_path, 'wb') as f:
                f.write(private_key)

            # Set restrictive permissions on private key
            os.chmod(private_key_path, 0o600)

            print(f"Key pair generated successfully")
            print(f"  Public key:  {public_key_path}")
            print(f"  Private key: {private_key_path}")
            print(f"  Algorithm:   {PostQuantumFileEncryption.KEM_ALGORITHM}")

        except Exception as e:
            print(f"Error generating keypair: {e}")
            sys.exit(1)

    @staticmethod
    def _derive_aes_key(shared_secret: bytes) -> bytes:
        """
        Derive AES-256 key from shared secret using HKDF.

        Args:
            shared_secret: The shared secret from KEM

        Returns:
            32-byte AES-256 key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=PostQuantumFileEncryption.AES_KEY_SIZE,
            salt=None,
            info=b'file-encryption-aes-key',
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
        """
        Encrypt a file using ML-KEM-1024 and AES-256-GCM.

        Args:
            input_path: Path to file to encrypt
            output_path: Path where encrypted file will be saved
            public_key_path: Path to public key file
        """
        try:
            # Check if output file already exists
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                print("Refusing to overwrite. Please remove the file or choose a different path.")
                sys.exit(1)

            # Read public key
            with open(public_key_path, 'rb') as f:
                public_key = f.read()

            # Read input file
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            # Initialize KEM and encapsulate to get shared secret
            kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM)
            ciphertext_kem, shared_secret = kem.encap_secret(public_key)

            # Derive AES key from shared secret
            aes_key = PostQuantumFileEncryption._derive_aes_key(shared_secret)

            # Generate random nonce for AES-GCM
            nonce = os.urandom(PostQuantumFileEncryption.NONCE_SIZE)

            # Encrypt file data with AES-256-GCM
            aesgcm = AESGCM(aes_key)
            ciphertext_aes = aesgcm.encrypt(nonce, plaintext, None)

            # Write encrypted data to file
            # Format: [kem_ciphertext_length(4)][kem_ciphertext][nonce(12)][aes_ciphertext+tag]
            with open(output_path, 'wb') as f:
                # Write KEM ciphertext length (4 bytes, big-endian)
                kem_ct_len = len(ciphertext_kem)
                f.write(kem_ct_len.to_bytes(4, byteorder='big'))

                # Write KEM ciphertext (encapsulated shared secret)
                f.write(ciphertext_kem)

                # Write nonce
                f.write(nonce)

                # Write AES ciphertext (includes authentication tag)
                f.write(ciphertext_aes)

            print(f"File encrypted successfully")
            print(f"  Input:  {input_path} ({len(plaintext)} bytes)")
            print(f"  Output: {output_path}")
            print(f"  Using:  {PostQuantumFileEncryption.KEM_ALGORITHM} + AES-256-GCM")

        except FileNotFoundError as e:
            print(f"Error: File not found - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error encrypting file: {e}")
            sys.exit(1)

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
        """
        Decrypt a file using ML-KEM-1024 and AES-256-GCM.

        Args:
            input_path: Path to encrypted file
            output_path: Path where decrypted file will be saved
            private_key_path: Path to private key file
        """
        try:
            # Check if output file already exists
            if os.path.exists(output_path):
                print(f"Error: Output file already exists: {output_path}")
                print("Refusing to overwrite. Please remove the file or choose a different path.")
                sys.exit(1)

            # Read private key
            with open(private_key_path, 'rb') as f:
                private_key = f.read()

            # Read encrypted file
            with open(input_path, 'rb') as f:
                # Read KEM ciphertext length
                kem_ct_len = int.from_bytes(f.read(4), byteorder='big')

                # Read KEM ciphertext
                ciphertext_kem = f.read(kem_ct_len)

                # Read nonce
                nonce = f.read(PostQuantumFileEncryption.NONCE_SIZE)

                # Read AES ciphertext + tag
                ciphertext_aes = f.read()

            # Initialize KEM with private key and decapsulate to recover shared secret
            kem = oqs.KeyEncapsulation(PostQuantumFileEncryption.KEM_ALGORITHM, secret_key=private_key)
            shared_secret = kem.decap_secret(ciphertext_kem)

            # Derive AES key from shared secret
            aes_key = PostQuantumFileEncryption._derive_aes_key(shared_secret)

            # Decrypt file data with AES-256-GCM
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_aes, None)

            # Write decrypted data to file
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            print(f"File decrypted successfully")
            print(f"  Input:  {input_path}")
            print(f"  Output: {output_path} ({len(plaintext)} bytes)")

        except FileNotFoundError as e:
            print(f"Error: File not found - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error decrypting file: {e}")
            print("  This could be due to:")
            print("  - Wrong private key")
            print("  - Corrupted encrypted file")
            print("  - File was not encrypted with this tool")
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

    # Output
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
