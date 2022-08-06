#!/bin/bash

set -e

export KEY=$(cargo run --bin tshl -- key-gen -o key.priv)

cargo run --bin tshl -- listen -k key.priv -a "127.0.0.1:2000" &

sleep 1

cargo run --bin tshr -- "127.0.0.1" ${KEY}
