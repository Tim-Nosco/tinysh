#!/bin/bash

# Uncomment for a statically linked build
export RUSTFLAGS='-C target-feature=+crt-static'

cargo +nightly build \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target mipsel-unknown-linux-uclibc \
    --release
