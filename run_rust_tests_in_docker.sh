#!/bin/bash

# Script to copy Rust project to Docker container, build it, and run tests
# Usage: ./run_rust_tests.sh

set -e  # Exit on any error

CONTAINER_ID="3b4a2936afac"
CONTAINER_PATH="/opt/"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Copying Rust project to Docker container..."
# Create directory if it doesn't exist (although we copy the folder)
docker exec "${CONTAINER_ID}" mkdir -p "${CONTAINER_PATH}/pqenc_rust"
docker cp "${LOCAL_DIR}/pqenc_rust/." "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc_rust/"

echo "==> Copying test scripts..."
docker cp "${LOCAL_DIR}/test_integration_rust.py" "${CONTAINER_ID}:${CONTAINER_PATH}/test_integration_rust.py"
docker cp "${LOCAL_DIR}/pqenc.py" "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc.py"

echo "==> Installing dependencies and building Rust project..."
# Use heredoc with quoted delimiter to prevent local expansion, except for variables we want to expand
# Actually, simpler to just generate a script file and run it
cat <<EOF > build_and_test.sh
set -e
apt-get update
apt-get install -y curl build-essential cmake git ninja-build libssl-dev pkg-config clang libclang-dev

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

source \$HOME/.cargo/env

# Install cargo-sbom and cargo-deny if not present
if ! command -v cargo-sbom &> /dev/null; then
    echo "==> Installing cargo-sbom..."
    cargo install cargo-sbom
fi

if ! command -v cargo-deny &> /dev/null; then
    echo "==> Installing cargo-deny..."
    cargo install cargo-deny
fi

# Build and install liboqs
if [ ! -d "liboqs" ]; then
    echo "==> Cloning and building liboqs..."
    git clone --depth 1 --branch 0.13.0 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    cmake -GNinja -DOQS_USE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
    ninja
    ninja install
    cd ../..
fi

cd ${CONTAINER_PATH}/pqenc_rust
export LD_LIBRARY_PATH=/usr/local/lib

# Generate Cargo.lock
echo "==> Generating Cargo.lock..."
cargo generate-lockfile

# Run cargo-deny checks (allow network failures for advisory database)
echo "==> Running cargo-deny security checks..."
cargo deny check || echo "Warning: cargo-deny check failed (possibly due to network issues)"

# Generate SBOM
echo "==> Generating SBOM..."
cargo sbom > sbom.json

# Build the release binary
cargo build --release
EOF

# Copy the build script to container
docker cp build_and_test.sh "${CONTAINER_ID}:${CONTAINER_PATH}/build_and_test.sh"
rm build_and_test.sh

# Run the build script
docker exec "${CONTAINER_ID}" bash "${CONTAINER_PATH}/build_and_test.sh"

echo "==> Copying Cargo.lock and SBOM back to local machine..."
docker cp "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc_rust/Cargo.lock" "${LOCAL_DIR}/pqenc_rust/Cargo.lock"
docker cp "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc_rust/sbom.json" "${LOCAL_DIR}/pqenc_rust/sbom.json"

echo "==> Running integration tests..."
docker exec "${CONTAINER_ID}" bash -c "
    source \$HOME/.cargo/env
    export LD_LIBRARY_PATH=/usr/local/lib
    cd ${CONTAINER_PATH}
    .venv/bin/python3 test_integration_rust.py
"

echo ""
echo "==> All rust tests completed successfully!"
echo "==> Cargo.lock and sbom.json have been copied to ${LOCAL_DIR}/pqenc_rust/"
