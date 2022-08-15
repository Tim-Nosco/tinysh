#!/bin/bash

cargo bloat \
    --target mipsel-unknown-linux-musl \
    --bin tshr \
    --profile bloat \
    -Zbuild-std=std,core,alloc,panic_abort \
    -Zbuild-std-features=panic_immediate_abort \
    $@
