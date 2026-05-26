# Development Guide

## Update everything to latest

```bash
cargo upgrade --incompatible
cargo test
cargo audit
cargo deny check
```

Review changelogs for crypto crates before committing:
- [libcrux-ml-kem](https://github.com/cryspen/libcrux/releases)
- [aes-gcm](https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/CHANGELOG.md)
- [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/blob/main/x25519-dalek/CHANGELOG.md)
- [argon2](https://github.com/RustCrypto/password-hashes/blob/master/argon2/CHANGELOG.md)

## Update toolchain

```bash
rustup update stable
cargo test
```
