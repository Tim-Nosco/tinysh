#!/bin/bash

export KEY="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPdpKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w=="

cargo run --bin tshr -- "127.0.0.1" ${KEY}
