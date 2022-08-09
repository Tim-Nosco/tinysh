#!/bin/bash

MIPSEL=mipsel-linux-musl-cross.tgz
if [ ! -f $MIPSEL ]; then
    wget https://musl.cc/mipsel-linux-musl-cross.tgz && tar xzf mipsel-linux-musl-cross.tgz
fi

cargo +nightly build \
    -Z build-std=std,core,alloc,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target mipsel-unknown-linux-musl \
    --bin tshr \
    --release

cargo +nightly build \
    -Z build-std=std,core,alloc,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target x86_64-unknown-linux-gnu \
    --bin tshl \
    --release

du -h ./target/mipsel-unknown-linux-musl/release/tshr
du -h ./target/x86_64-unknown-linux-gnu/release/tshl
