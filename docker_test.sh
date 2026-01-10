#!/bin/bash
# Build Docker image and run x86_64 tests
# Usage: ./docker_test.sh [--build-image]

set -e

IMAGE_NAME="cot-x86_64"
DOCKERFILE="Dockerfile.x86_64"

# Check if we need to build/rebuild the image
if [ "$1" = "--build-image" ] || [ "$1" = "-b" ]; then
    echo "Building Docker image..."
    docker build --platform linux/amd64 -t "$IMAGE_NAME" -f "$DOCKERFILE" .
    echo "Image built successfully."
    echo ""
fi

# Check if image exists
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image '$IMAGE_NAME' not found. Building..."
    docker build --platform linux/amd64 -t "$IMAGE_NAME" -f "$DOCKERFILE" .
    echo ""
fi

# Build cot for x86_64
echo "Building cot for x86_64-linux-gnu..."
zig build -Dtarget=x86_64-linux-gnu
echo ""

# Run tests in Docker
echo "Running tests in Docker container..."
docker run --rm --platform linux/amd64 -v "$(pwd):/cot" "$IMAGE_NAME" ./run_tests_x86_64.sh
