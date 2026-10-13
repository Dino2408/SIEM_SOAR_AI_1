#!/usr/bin/env bash
set -e

VERSION_TAG="v002"
OUTPUT_DIR="../../dist_releases"
ARCHIVE_NAME="secops_portable_${VERSION_TAG}.tar.gz"

mkdir -p "$OUTPUT_DIR"

echo "=========================================================="
echo " [SECOPS PACKAGE] Packaging Portable Bundle: $VERSION_TAG"
echo "=========================================================="

if [ "$1" == "--with-images" ]; then
    echo "[+] Exporting Docker Images for Air-gapped offline deployment..."
    docker save \
        secops_${VERSION_TAG}-siem:latest \
        secops_${VERSION_TAG}-ai-triage:latest \
        secops_${VERSION_TAG}-guardrails:latest \
        secops_${VERSION_TAG}-soar:latest \
        secops_${VERSION_TAG}-vector:latest \
        secops_${VERSION_TAG}-seed-test:latest \
        redpandadata/redpanda:v24.1.2 \
        qdrant/qdrant:v1.9.0 \
        -o "${OUTPUT_DIR}/secops_images_${VERSION_TAG}.tar"
    echo "[+] Saved Docker images to ${OUTPUT_DIR}/secops_images_${VERSION_TAG}.tar"
fi

echo "[+] Creating portable tarball..."
tar -czf "${OUTPUT_DIR}/${ARCHIVE_NAME}" \
    --exclude="test_results/*.json" \
    --exclude=".env" \
    --exclude="__pycache__" \
    -C .. "$(basename "$PWD")"

echo "[+] Release bundle successfully generated: ${OUTPUT_DIR}/${ARCHIVE_NAME}"
echo "=========================================================="
