#!/bin/bash
# Check that the remote part of the project will build for all the architectures
# we can support.
set -euo pipefail

# Map the rust target triple we support to the musl version of the triple.
declare -A rust2musl
rust2musl[aarch64-unknown-linux-musl]=aarch64-linux-musl
rust2musl[arm-unknown-linux-musleabi]=arm-linux-musleabi
rust2musl[i686-unknown-linux-musl]=i686-linux-musl
rust2musl[mips-unknown-linux-musl]=mips-linux-musl
rust2musl[mips64-unknown-linux-muslabi64]=mips64-linux-musl
rust2musl[mips64el-unknown-linux-muslabi64]=mips64el-linux-musl
rust2musl[mipsel-unknown-linux-musl]=mipsel-linux-musl
rust2musl[x86_64-unknown-linux-musl]=x86_64-linux-musl

for rust_target in "${!rust2musl[@]}"; do
    musltriple="${rust2musl[$rust_target]}"
    sysrootdir="$musltriple-cross"
    tarball="$sysrootdir.tgz"
    url="https://musl.cc/$tarball"

    if [ ! -d "$sysrootdir" ]; then
        echo "[+] installing $rust_target toolchain"
        if [ ! -f "$tarball" ]; then
            wget -q "$url" && tar xzf "$tarball"
        else
            tar xzf "$tarball"
        fi
    fi

    echo "[+] compiling $rust_target"
    cargo build \
        --target "$rust_target" \
        --bin tshr \
        -Zbuild-std=std,core,panic_abort \
        -Zbuild-std-features=panic_immediate_abort \
        --release -q

    du -h "./target/$rust_target/release/tshr"
done
