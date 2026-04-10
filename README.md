# pqenc

Post-quantum encryption tool using ML-KEM-1024 (NIST FIPS 203) and AES-256-GCM with formally verified cryptography.

## Overview

pqenc is designed for encrypting backups and archives using asymmetric encryption, so that the machine doing the encrypting never needs access to the private key.

The intended workflow is:

- **The backup machine** holds only the public key and runs encryption. If this machine is ever compromised, the attacker cannot decrypt any of the backup data.
- **The private key** is generated once and stored securely offline — on an encrypted drive, hardware token, or air-gapped computer. It is only needed when restoring data.
- **Encryption can run unattended** (e.g. as a cron job or scheduled task) since it only requires the public key.

Using ML-KEM-1024 ensures that the encrypted data remains secure against future quantum computers, which can break the RSA and ECC algorithms used by most current encryption tools.

## Features

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum key encapsulation mechanism
- **X25519** - Hybrid classical key exchange for defense in depth
- **AES-256-GCM** - Authenticated encryption with additional data
- **Formally verified** - Uses libcrux, a formally verified cryptography library
- **Pure Rust** - No C dependencies required
- **Stdin support** - Encrypt piped data (e.g. tar archives) directly without writing plaintext to disk

## Quick Start

```bash
pqenc generate-keys -p pub.key -s priv.key
pqenc encrypt -i secret.txt -o secret.txt.pqe -p pub.key
pqenc decrypt -i secret.txt.pqe -o secret.txt -s priv.key
```

## Typical Workflow

### 1. Generate a keypair (once, on a secure machine)

```bash
pqenc generate-keys --public-key pub.key --private-key priv.key
```

Store `priv.key` somewhere secure and offline. Copy `pub.key` to the machine that will be doing backups.

### 2. Encrypt backups (regularly, on the backup machine)

```bash
# Encrypt a single file
pqenc encrypt --encrypt data.tar.gz --output data.tar.gz.pqe --public-key pub.key

# Encrypt a directory without writing plaintext to disk
tar czf - /path/to/data | pqenc encrypt --encrypt - --output backup.tar.gz.pqe --public-key pub.key
```

### 3. Decrypt to restore (only when needed, using the private key)

```bash
pqenc decrypt --decrypt backup.tar.gz.pqe --output backup.tar.gz --private-key priv.key
```

If preferred, decryption can be performed on an offline or air-gapped machine by transferring the encrypted file there.

## Building

### Prerequisites

- Rust 1.70 or later
- No system dependencies required — all cryptographic primitives are pure Rust crates

### Build Commands

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

For detailed testing documentation, see [TESTING.md](TESTING.md).

## License

MIT OR Apache-2.0
