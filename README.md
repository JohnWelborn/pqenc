# pqenc

Post-quantum encryption tool using ML-KEM-1024 (FIPS 203) and AES-256-GCM with formally verified cryptography.

## Features

- **ML-KEM-1024** (NIST FIPS 203) - Post-quantum key encapsulation mechanism
- **X25519** - Hybrid classical key exchange for defense in depth
- **AES-256-GCM** - Authenticated encryption with additional data
- **Formally verified** - Uses libcrux, a formally verified cryptography library
- **Pure Rust** - No C dependencies required

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
