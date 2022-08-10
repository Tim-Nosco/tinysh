#!/bin/bash

set -e

export ARCH="--target ""$(rustc -vV | grep -oP '(?<=host: )\S+')"

export KEY=$(cargo run --bin tshl $ARCH -- key-gen -o key.priv)

cargo run --bin tshl $ARCH -- listen -k key.priv -a "127.0.0.1:2000" &

sleep 1

cargo run --bin tshr $ARCH -- "127.0.0.1" ${KEY}
