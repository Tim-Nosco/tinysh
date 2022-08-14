#!/bin/bash

MIPSEL=mipsel-linux-musl-cross.tgz
if [ ! -f $MIPSEL ]; then
    wget https://musl.cc/mipsel-linux-musl-cross.tgz && tar xzf mipsel-linux-musl-cross.tgz
fi

cargo build \
    --target mipsel-unknown-linux-musl \
    --bin tshr \
    --release \
    -Zbuild-std=std,core,alloc,panic_abort \
    -Zbuild-std-features=panic_immediate_abort

cargo build \
    --target x86_64-unknown-linux-gnu \
    --bin tshl \
    --release

du -h ./target/mipsel-unknown-linux-musl/release/tshr
du -h ./target/x86_64-unknown-linux-gnu/release/tshl
