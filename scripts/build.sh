#!/bin/bash

# statically linked build
export RUSTFLAGS='-C target-feature=+crt-static'

export CC=mipsel-buildroot-linux-uclibc-gcc
export CXX=mipsel-buildroot-linux-uclibc-g++
cargo +nightly build \
    -Z build-std=std,core,alloc,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target mipsel-unknown-linux-uclibc \
    --bin tshr \
    --release

export CC=""
export CXX=""
#export RUSTFLAGS=""
cargo +nightly build \
    -Z build-std=std,core,alloc,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target x86_64-unknown-linux-gnu \
    --bin tshl \
    --release

du -h ./target/mipsel-unknown-linux-uclibc/release/tshr
