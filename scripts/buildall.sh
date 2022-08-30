#!/bin/bash
# Check that the remote part of the project will build for all the architectures
# we can support.
set -euo pipefail

# Map the rust target triple we support to the musl version of the triple.
# Note that each rust target we specify must also be listed in the
# rust-toolchain.toml file, under 'targets'
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
        if [ ! -f "$tarball" ]; then
            wget -q "$url" && tar xzf "$tarball"
        else
            tar xzf "$tarball"
        fi
    fi

    compiler="$musltriple-gcc"
    export RUSTFLAGS="-Ctarget-feature=+crt-static"
    echo "[+] compiling $rust_target"
    cargo build \
        --config "target.$rust_target.linker=\"$sysrootdir/bin/$compiler\"" \
        --target "$rust_target" \
        --bin tshr \
        -Zbuild-std=std,core,alloc,panic_abort \
        -Zbuild-std-features=panic_immediate_abort \
        --release -q

    du -h "./target/$rust_target/release/tshr"
    echo ""
done
