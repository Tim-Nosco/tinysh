#!/bin/bash

set -e

./scripts/build.sh

qemu-mipsel-static ./target/mipsel-unknown-linux-musl/release/tshr "127.0.0.1:2000" $1
