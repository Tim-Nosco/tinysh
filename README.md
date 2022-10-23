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

If you want to build TSH from source (instead of downloading from the official
release), it requires some setup to make sure the resulting binary is as small
as possible. In order of least to most amount of work on your part:

### Build in a Docker container

The main benefit is that all the toolchains and rust components end up in a
Docker image instead of in your standard environment.

```bash
docker build -t tinysh-build .
docker run --rm -it -v $PWD:/root tinysh-build ./scripts/build.sh <supported rust target triple> 
```

### Build using a script

If you're fine with downloading musl toolchains and updating your rust
installation, you can just use our build script directly.

```bash
./scripts/build.sh <supported rust target triple>
```

### Build manually

Want to run `cargo` yourself? You can do that too.

```bash
# To build the remote side
cargo build \
    --target <supported rust target> \
    --bin tshr \
    --release \
    -Zbuild-std=std,core,panic_abort \
    -Zbuild-std-features=panic_immediate_abort
# To build the local side
cargo build --bin tshl --release
```

## For Contributors

We have a few scripts that you can use to make development and testing easier.

### Building for all targets

Quickly test that the remote still builds for all supported targets by running
`./scripts/build_remote_all_arches.sh`.

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

### Check what's taking all that space

Use `./scripts/bloat.sh` to compile the remote and get a report on what
sections use the most space in the binary. (You'll need to install the `cargo
bloat` tool with `cargo install cargo-bloat`.)

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
