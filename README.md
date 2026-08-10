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
pqenc generate-keys -p pub.key -s priv.key
```

**2. Encrypt with the public key:**

```bash
pqenc encrypt bank.txt -p pub.key -o secret.pqe
```

**3. Decrypt with the private key:**

```bash
pqenc decrypt secret.pqe -s priv.key
```

**Encrypting a directory (tar+gzip streamed internally, never written to disk):**

```bash
pqenc encrypt mydir -p pub.key
```

## Features

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum key encapsulation mechanism
- **X25519** - Hybrid classical key exchange for defense in depth
- **AES-256-GCM** - Authenticated encryption with additional data
- **Segmented rekeying (PQE4, also reads legacy PQE3)** - the current format `pqenc encrypt` writes divides plaintext into fixed 8 GiB segments, each independently keyed via HKDF-SHA256, so no single AES-256-GCM key ever encrypts more than 8 GiB regardless of total file size; `pqenc decrypt`/`pqenc verify` also still read files from the older PQE3 format
- **Formally verified** - Uses libcrux, a formally verified cryptography library
- **Pure Rust** - No C dependencies required
- **Stdin support** - Encrypt piped data (e.g. tar archives) directly without writing plaintext to disk
- **Atomic output** - Encryption streams to a temporary file and renames it into place, so an interrupted run never leaves a partial file that looks like a completed backup; if a hard kill or power loss interrupts before the rename, pqenc recognizes its own leftover reservation placeholder and safely reclaims it on the next attempt to the same path
- **Key fingerprints & randomart** - `ssh-keygen`-style `SHA256:` fingerprints and ASCII-art visualization, shown at key generation and encryption time and available on demand via `pqenc fingerprint`, so a mismatched keypair can be caught by eye instead of only at restore time
- **Metadata restoration** - the original filename, modification time, and access time are captured, encrypted, and authenticated at encrypt time, and restored automatically on decrypt when `--output` is omitted; restoration is best-effort and never fails the decrypt
- **Corruption detection without the private key** - every encrypted file carries a SHA-256 checksum trailer over its own bytes, computed incrementally during encryption; `pqenc verify` recomputes and compares it, plus magic-byte/structural checks, with no key or passphrase, so it's safe to run unattended, e.g. in cron right after each backup. `pqenc decrypt` also runs this same check automatically, as a preflight before touching the private key, so a corrupted file is rejected with a clear error up front rather than partway through decryption. This is a plain checksum, not cryptographic authentication: it catches accidental corruption (bit rot, truncation, a bad copy), not deliberate tampering. Deliberate tampering is still caught by the AEAD tags at actual decrypt time

## Typical Workflow

See [USAGE.md](USAGE.md) for the full walkthrough

## Building

### Prerequisites

- Rust 1.95 or later
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
