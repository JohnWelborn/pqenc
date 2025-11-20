#!/bin/bash

# Script to copy pqenc.py to Docker container and run tests
# Usage: ./run_tests_in_docker.sh

set -e  # Exit on any error

CONTAINER_ID="3b4a2936afac"
CONTAINER_PATH="/opt/"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Copying pqenc.py to Docker container..."
docker cp "${LOCAL_DIR}/pqenc.py" "${CONTAINER_ID}:${CONTAINER_PATH}/pqenc.py"

echo "==> Copying test_python.py to Docker container..."
docker cp "${LOCAL_DIR}/test_python.py" "${CONTAINER_ID}:${CONTAINER_PATH}/test_python.py"

echo "==> Copying test_integration_python.py to Docker container..."
docker cp "${LOCAL_DIR}/test_integration_python.py" "${CONTAINER_ID}:${CONTAINER_PATH}/test_integration_python.py"

echo "==> Running unit tests in Docker container..."
docker exec "${CONTAINER_ID}" bash -c "cd ${CONTAINER_PATH} && .venv/bin/pytest test_python.py -v"

echo "==> Running integration tests in Docker container..."
docker exec "${CONTAINER_ID}" bash -c "cd ${CONTAINER_PATH} && .venv/bin/python3 test_integration_python.py"

echo ""
echo "==> All tests completed successfully!"
