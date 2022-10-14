# TinySH v0.1.0

TinySH is a statically-compiled UNIX backdoor written in the rust programming language.
We agressively optimize for size and have selected a minimal set of features 
to securely administer a remote system.

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
| mips64-unknown-linux-muslabi64    | 88K       |
| mipsel-unknown-linux-musl         | 88K       |
| mips-unknown-linux-musl           | 88K       |
| i686-unknown-linux-musl           | 76K       |
| x86\_64-unknown-linux-musl        | 76K       |
| aarch64-unknown-linux-musl        | 56K       |
| arm-unknown-linux-musleabi        | 68K       |

## Building

You can use `docker` to build TSH by running: 

`./scripts/docker.sh`

and then

`ARCH='x86_64' LIBC='musl' ./scripts/build.sh`

Ensure to change the `ARCH` and `LIBC` variables to match your desired build from the table above.

If you don't have docker, you'll need [rustup](https://rustup.rs/). 
After you have that, you should be able to use the build script above.

### Building for all arches

To do this, use the helper script `scripts/buildall.sh`

### Building for development

As demonstrated in `scripts/run_debug.sh`, you can do the following to run the local side:

```
# build a new key
cargo run --bin tshl $ARCH -- key-gen -o key.priv

# start the local client
cargo run --bin tshl $ARCH -- listen -k key.priv -a "127.0.0.1:2000"
```

Take note of the public key output by the local client, this is used in the argv of the remote.
In a new terminal, you can start the remote side:

```
# start the remote client
cargo run --bin tshr $ARCH -- "127.0.0.1:2000" ${KEY}
```

## Other Notes

The remote client is designed to be a single-use connection. 
It calls home, decides what to do, does the thing, and then exits.
It's worth while to consider running it in a loop to call home multiple times if desired.

## Future Features

1. More unit tests
1. Fuzzing
1. GitHub CI to build releases automatically
1. Get/Put/Execute
1. Socks proxy

## References

TSH makes heavy use of the materials from:
- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)
- [Tighten rust's belt](https://dl.acm.org/doi/abs/10.1145/3519941.3535075)
- [Embedded Rust Book](https://docs.rust-embedded.org/book/)
