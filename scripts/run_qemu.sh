#!/bin/bash

set -e

./scripts/build.sh

export KEY="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPdpKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w=="

qemu-mipsel-static $@ ./target/mipsel-unknown-linux-uclibc/release/tshr "127.0.0.1" ${KEY}
