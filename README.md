# pqenc

Post-quantum encryption in Rust. Encrypt backups with a public key, keep the private key offline.

ML-KEM-1024 formally verified cryptography + X25519 hybrid key exchange (NIST FIPS 203) + AES-256-GCM

## Disclaimer

This repository was built as an exercise in AI-assisted coding.

## Overview

pqenc is designed for encrypting backups and archives using asymmetric encryption, so that the machine doing the encrypting never needs access to the private key.

The intended workflow is:

- **The backup machine** holds only the public key and runs encryption. If this machine is ever compromised, the attacker cannot decrypt any of the backup data.
- **The private key** is generated once and stored securely offline — on an encrypted drive, hardware token, or air-gapped computer, together with the passphrase protecting it. It is only needed when restoring data.
- **Encryption can run unattended** (e.g. as a cron job or scheduled task) since it only requires the public key.

Using ML-KEM-1024 ensures that the encrypted data remains secure against future quantum computers, which can break the RSA and ECC algorithms used by most current encryption tools.

## Quick Start

**1. Generate a keypair, secure priv.key offline:**

```bash
pqenc generate-keys
```

**2. Encrypt with the public key:**

```bash
pqenc encrypt secret.txt --output bank.pqe
```

**3. Decrypt with the private key:**

```bash
pqenc decrypt secret.pqe
```

**Default key location:** `-p`/`-s` can be omitted. `generate-keys` then writes to `~/.pqenc/pub.key` and `~/.pqenc/priv.key` (creating that directory, owner-only, if needed), and `encrypt`/`decrypt`/`fingerprint` read from there when no key is given:

```bash
pqenc generate-keys
pqenc encrypt bank.txt -o secret.pqe
pqenc decrypt secret.pqe
```

This is a convenience for single-machine use. For the offline-private-key workflow described above, move (or copy) `~/.pqenc/priv.key` to offline storage after generating it — the default location does not do that for you.

**Encrypting a directory (tar+gzip streamed internally, never written to disk):**

```bash
pqenc encrypt mydir --output secret.pqe
```

## Features

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum key encapsulation mechanism
- **X25519** - Hybrid classical key exchange for defense in depth
- **AES-256-GCM** - Authenticated encryption with additional data
- **Formally verified ML-KEM-1024** - Uses libcrux, a formally verified cryptography library
- **Pure Rust** - No C dependencies required
- **Stdin support** - Encrypt piped data (e.g. tar archives) directly without writing plaintext to disk
- **Atomic output** - Encryption streams to a temporary file and renames it into place, so an interrupted run never leaves a partial file that looks like a completed backup
- **Key fingerprints & randomart** - `ssh-keygen`-style `SHA256:` fingerprints and ASCII-art visualization, shown at key generation and encryption time and available on demand via `pqenc fingerprint`, so a mismatched keypair can be caught by eye instead of only at restore time
- **Metadata restoration** - the original filename, modification time, and access time are captured, encrypted, and authenticated at encrypt time, and restored automatically on decrypt
- **Corruption detection without the private key** - every encrypted file carries a SHA-256 checksum trailer, checked by `pqenc verify` and `pqenc decrypt`. It catches accidental corruption (bit rot, truncation, a bad copy), not tampering

## Typical Workflow

See [USAGE.md](USAGE.md) for the full walkthrough

## Building

### Prerequisites

- Rust 1.95 or later
- No system dependencies required — all cryptographic primitives are pure Rust crates

### Build Commands

```bash
# Release build
cargo build --release

# Run tests
cargo test
```

For detailed testing documentation, see [TESTING.md](TESTING.md).

## License

MIT OR Apache-2.0
