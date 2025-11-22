#!/bin/bash

# Script to run comprehensive Python ↔ Rust interoperability tests in Docker
# Usage: ./run_together_tests_in_docker.sh

set -e  # Exit on any error

CONTAINER_ID="3b4a2936afac"
CONTAINER_PATH="/opt/"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================================"
echo "  Python ↔ Rust Interoperability Test Suite"
echo "============================================================"

echo ""
echo "==> Copying Rust project to Docker container..."
docker exec "${CONTAINER_ID}" mkdir -p "${CONTAINER_PATH}/pqenc_rust"
docker cp "${LOCAL_DIR}/pqenc_rust/." "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc_rust/"

echo "==> Copying Python implementation and test scripts..."
docker cp "${LOCAL_DIR}/test_integration_together.py" "${CONTAINER_ID}:${CONTAINER_PATH}/test_integration_together.py"
docker cp "${LOCAL_DIR}/pqenc.py" "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc.py"

echo "==> Setting up build environment..."
# Create build script
cat <<'EOF' > build_script.sh
set -e

# Update package list
apt-get update -qq

# Install dependencies if not present
apt-get install -y curl build-essential cmake git ninja-build libssl-dev pkg-config clang libclang-dev 2>&1 | grep -v "already the newest version" || true

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
fi

# Source Rust environment
source $HOME/.cargo/env

# Build and install liboqs if not present
if [ ! -d "liboqs" ]; then
    echo "Building liboqs (this may take a few minutes)..."
    git clone --depth 1 --branch 0.13.0 https://github.com/open-quantum-safe/liboqs.git 2>&1 | head -5
    cd liboqs
    mkdir build && cd build
    cmake -GNinja -DOQS_USE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. > /dev/null
    ninja > /dev/null 2>&1
    ninja install > /dev/null 2>&1
    cd ../..
    echo "✅ liboqs installed"
else
    echo "✅ liboqs already installed"
fi

# Build Rust project
cd /opt/pqenc_rust
export LD_LIBRARY_PATH=/usr/local/lib

# Check if already built
if [ ! -f "target/release/pqenc" ]; then
    echo "Building Rust implementation..."
    cargo build --release 2>&1 | grep -E "(Compiling|Finished)" || true
    echo "✅ Rust build complete"
else
    echo "✅ Rust binary already built"
fi
EOF

# Copy and run build script
docker cp build_script.sh "${CONTAINER_ID}:${CONTAINER_PATH}/build_script.sh"
rm build_script.sh

echo ""
docker exec "${CONTAINER_ID}" bash "${CONTAINER_PATH}/build_script.sh"

echo ""
echo "============================================================"
echo "  Running Interoperability Tests"
echo "============================================================"
echo ""

# Run the comprehensive test suite
docker exec "${CONTAINER_ID}" bash -c "
    source \$HOME/.cargo/env
    export LD_LIBRARY_PATH=/usr/local/lib
    cd ${CONTAINER_PATH}

    # Make test executable
    chmod +x test_integration_together.py

    # Run tests
    .venv/bin/python3 test_integration_together.py
"

echo ""
echo "============================================================"
echo "  ✅ All Interoperability Tests Passed!"
echo "============================================================"
echo ""
echo "Verified:"
echo "  • Python → Rust encryption/decryption"
echo "  • Rust → Python encryption/decryption"
echo "  • Self-decryption for both implementations"
echo "  • Truncation attack detection"
echo "  • Wrong key rejection"
echo ""
