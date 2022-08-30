# TinySH v0.1.0

TinySH is a statically-compiled UNIX backdoor written in the rust programming language.
We agressively optimize for size and have selected a minimal set of features 
to securly administer a remote system.

## Overview

![Control Flow Graph](/docs/images/control-flow.png)

### Supported Architectures

| Target Triple                     | Size      |
| --------------------------------- | --------- |
| mips64el-unknown-linux-muslabi64  | 88K       |
| mips-unknown-linux-musl           | 88K       |
| mipsel-unknown-linux-musl         | 88K       |
| i686-unknown-linux-musl           | 76K       |
| mips64-unknown-linux-muslabi64    | 88K       |
| x86\_64-unknown-linux-musl        | 76K       |
| aarch64-unknown-linux-musl        | 56K       |
| arm-unknown-linux-musleabi        | 68K       |

## Building



## References

TSH makes heavy use of the materials from:
- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)
- [Tighten rust's belt](https://dl.acm.org/doi/abs/10.1145/3519941.3535075)
- [Embedded Rust Book](https://docs.rust-embedded.org/book/)
