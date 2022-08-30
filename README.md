# TinySH v0.1.0

TinySH is a statically-compiled UNIX backdoor written in the rust programming language.
We agressively optimize for size and have selected a minimal set of features 
to securly administer a remote system.

## Overview

![Control Flow Graph](/docs/images/control-flow.png)

### Actions

- Shell: This sets up a nice TTY environment that captures `CTRL-C`, arrows, backspace, and other niceties.
Then, it calls the remote's `/bin/sh`, piping `STDIO` over the relay.
- Put\*: This will put a file from the local machine to the remote machine.
- Get\*: This will get a file from the remote machine and save it to the local machine.
- Execute\*: This will execute a file on the remote machine.

\* Planned feature for release in v0.2.0

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

### Dependencies

You can use `docker` to build TSH by running: 

`./scripts/docker.sh`

and then

`./scripts/build.sh`

Ensure to change the `ARCH` and `LIBC` variables to match your desired build from the table above.

### Building for all arches

To do this, use the helper script `scripts/build_all.sh`

### Building for a specific arch

## Future Features

## References

TSH makes heavy use of the materials from:
- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)
- [Tighten rust's belt](https://dl.acm.org/doi/abs/10.1145/3519941.3535075)
- [Embedded Rust Book](https://docs.rust-embedded.org/book/)
