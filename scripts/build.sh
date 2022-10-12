#!/bin/bash
# Build the remote and local binaries.
# Build the remote for the specified target (defaulting to
# mipsel-unknown-linux-musl), and build the local for the host target.
set -euo pipefail

TARGET=${1:-}
if [ -z "${TARGET}" ]
then
    TARGET="mipsel-unknown-linux-musl"
fi

# shellcheck source=scripts/supported_arches.sh
source "$(dirname "$0")/supported_arches.sh"

download_musl_toolchain $TARGET

cargo build \
    --target "${TARGET}" \
    --bin tshr \
    --release \
    -Zbuild-std=std,core,panic_abort \
    -Zbuild-std-features=panic_immediate_abort

host=$(rustc -vV | grep -oP '(?<=host: ).*$')

cargo build \
    --target "${host}" \
    --bin tshl \
    --release

du -h "./target/${TARGET}/release/tshr"
du -h "./target/${host}/release/tshl"
