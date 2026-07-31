# pqenc

Post-quantum encryption tool using ML-KEM-1024 (NIST FIPS 203) and AES-256-GCM with formally verified cryptography.

## Disclaimer

This repository was built as an exercise in AI-assisted coding.

## Overview

pqenc is designed for encrypting backups and archives using asymmetric encryption, so that the machine doing the encrypting never needs access to the private key.

The intended workflow is:

- **The backup machine** holds only the public key and runs encryption. If this machine is ever compromised, the attacker cannot decrypt any of the backup data.
- **The private key** is generated once and stored securely offline — on an encrypted drive, hardware token, or air-gapped computer, together with the password protecting it. It is only needed when restoring data.
- **Encryption can run unattended** (e.g. as a cron job or scheduled task) since it only requires the public key.

Using ML-KEM-1024 ensures that the encrypted data remains secure against future quantum computers, which can break the RSA and ECC algorithms used by most current encryption tools.

## Features

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum key encapsulation mechanism
- **X25519** - Hybrid classical key exchange for defense in depth
- **AES-256-GCM** - Authenticated encryption with additional data
- **Formally verified** - Uses libcrux, a formally verified cryptography library
- **Pure Rust** - No C dependencies required
- **Stdin support** - Encrypt piped data (e.g. tar archives) directly without writing plaintext to disk
- **Atomic output** - Encryption streams to a temporary file and renames it into place, so an interrupted run never leaves a partial file that looks like a completed backup

## Quick Start

```bash
pqenc generate-keys -p pub.key -s priv.key
pqenc encrypt -p pub.key -i secret.txt -o secret.txt.pqe
pqenc decrypt -s priv.key -i secret.txt.pqe -o secret.txt
```

## Typical Workflow

### 1. Generate a keypair (once, on a secure machine)

```bash
pqenc generate-keys --public-key pub.key --private-key priv.key
```

Store `priv.key` somewhere secure and offline. Copy `pub.key` to the machine that will be doing backups.

**The password cannot be recovered.** `priv.key` is stored encrypted, and the
password is the only thing that opens it. There is no recovery path, no escrow,
and no way to export an unencrypted copy — pqenc has exactly three commands, and
none of them can help you here. Losing the password destroys your backups just as
completely as losing `priv.key` itself; neither half is any use without the other.

This is a deliberate design choice, and it means the password should be stored
**with** the offline private key rather than treated as an independent secret.
The two defend against different threats — the encrypted file protects against
someone who obtains your backups, the password protects against someone who
obtains the file — and neither threat is the one pqenc is built around. An
attacker who compromises the backup machine gets only `pub.key` either way.

### 2. Verify you can restore (once, before relying on any backup)

Do a full round trip with the keys you just generated:

```bash
echo "restore test" > test.txt
pqenc encrypt --public-key pub.key --encrypt test.txt --output test.pqe
pqenc decrypt --private-key priv.key --decrypt test.pqe --output test.out
cmp test.txt test.out && echo "restore verified"
```

This is currently the only way to catch a mismatched keypair — a `pub.key` and
`priv.key` that do not belong together, because keys were regenerated and only
one file was copied, or the wrong file was grabbed. Nothing in the file format
ties an encrypted file to a particular key, so encrypting to the wrong public key
succeeds and reports success every time. The mismatch surfaces only when you try
to restore, which may be months later. Repeat this check whenever you replace or
move either key file.

### 3. Encrypt backups (regularly, on the backup machine)

```bash
# Encrypt a single file
pqenc encrypt --public-key pub.key --encrypt data.tar.gz --output data.tar.gz.pqe

# Encrypt a directory without writing plaintext to disk
tar czf - /path/to/data | pqenc encrypt --public-key pub.key --encrypt - --output backup.tar.gz.pqe
```

Encrypted output is written with mode `0600` (owner read/write only). If a backup
agent running as a different user needs to read it, adjust permissions or ownership
after encryption.

Encryption refuses to overwrite an existing output file. Because output is written
atomically, a failed or interrupted run leaves no partial file behind, so the next
run is not blocked by a leftover stump.

### 4. Decrypt to restore (only when needed, using the private key)

```bash
pqenc decrypt --private-key priv.key --decrypt backup.tar.gz.pqe --output backup.tar.gz
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
