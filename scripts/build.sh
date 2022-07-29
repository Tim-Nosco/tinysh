#!/bin/bash

# statically linked build
export RUSTFLAGS='-C target-feature=+crt-static'

export CC=mipsel-buildroot-linux-uclibc-gcc
export CXX=mipsel-buildroot-linux-uclibc-g++

cargo +nightly build \
    -Z build-std \
    -Z build-std=std,core,alloc,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target mipsel-unknown-linux-uclibc \
    --release
