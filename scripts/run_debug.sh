#!/bin/bash

# stop on failure
set -em

# kill any running listeners
for x in $(netstat -tulpn | grep -oP '(\d+)(?=/target)'); do
    kill -9 $x
done

# determine our local arch
export ARCH="--target ""$(rustc -vV | grep -oP '(?<=host: )\S+')"

# build a new key
export KEY=$(cargo run --bin tshl $ARCH -- key-gen -o key.priv)

# start the local client
cargo run --bin tshl $ARCH -- listen -k key.priv -a "127.0.0.1:2000" &

# give it a moment to listen
sleep 1

# start the remote client
cargo run --bin tshr $ARCH -- "127.0.0.1" ${KEY} &

fg %1
