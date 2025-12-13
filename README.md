# pqenc

Post-quantum encryption tool using ML-KEM-1024 (Kyber) and AES-256-GCM.

## Building

### Prerequisites

This project requires OpenSSL 3.x for the liboqs dependency.

#### macOS

If you built OpenSSL from source (recommended for LTS version 3.5.4):

```bash
# Download and build OpenSSL 3.5.4 (LTS)
curl -O https://www.openssl.org/source/openssl-3.5.4.tar.gz
tar -xzf openssl-3.5.4.tar.gz
cd openssl-3.5.4

# Configure and install to /usr/local/openssl
./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
make
sudo make install
```

The `.cargo/config.toml` file is already configured to use OpenSSL at `/usr/local/openssl`.

If you installed OpenSSL to a different location, update `.cargo/config.toml` with the correct paths.

#### Alternative: Using Homebrew

```bash
brew install openssl@3 pkg-config
```

Then update `.cargo/config.toml`:
```toml
[env]
PKG_CONFIG_PATH = { value = "", relative = true, force = true }
```

And build with:
```bash
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
cargo build --release
```

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
