#!/bin/bash
# Check that the remote part of the project will build for all the
# architectures we can support.
set -euo pipefail

# shellcheck source=scripts/supported_arches.sh
source "$(dirname "$0")/supported_arches.sh"

download_all_musl_toolchains
for rust_target in "${!rust2musl[@]}"; do
    echo "[+] compiling $rust_target"
    cargo build \
        --target "$rust_target" \
        --bin tshr \
        -Zbuild-std=std,core,panic_abort \
        -Zbuild-std-features=panic_immediate_abort \
        --release -q

    du -h "./target/$rust_target/release/tshr"
done
