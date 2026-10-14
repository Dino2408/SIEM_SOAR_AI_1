#!/usr/bin/env bash
set -e

VERSION="v004"
RELEASE_DIR="../../dist_releases"
ARCHIVE_NAME="secops_portable_${VERSION}.tar.gz"

mkdir -p "${RELEASE_DIR}"

echo "Packaging ${VERSION} portable release archive..."
tar --exclude="./test_results/*" \
    --exclude="./.git" \
    --exclude="**/__pycache__" \
    -czvf "${RELEASE_DIR}/${ARCHIVE_NAME}" .

echo "Release package created at: ${RELEASE_DIR}/${ARCHIVE_NAME}"
