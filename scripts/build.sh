#!/bin/bash

if [ -z "${ARCH}" ]
then
    ARCH=mipsel
fi
if [ -z "${LIBC}" ]
then
    LIBC=musl
fi

TOOLCHAIN=${ARCH}-linux-${LIBC}-cross
TRIPLE=${ARCH}-unknown-linux-${LIBC}

if [ ! -f ${TOOLCHAIN}.tgz ]; then
    wget https://musl.cc/${TOOLCHAIN}.tgz && tar xzf ${TOOLCHAIN}
fi

cargo build \
    --target ${TRIPLE} \
    --bin tshr \
    --release \
    -Zbuild-std=std,core,panic_abort \
    -Zbuild-std-features=panic_immediate_abort

HOST=$(rustc -vV | grep -oP '(?<=host: ).*$')

cargo build \
    --target ${HOST} \
    --bin tshl \
    --release \

du -h ./target/${TRIPLE}/release/tshr
du -h ./target/${HOST}/release/tshl
