from ubuntu:22.04

run apt update && apt install -y \
    curl \
    gcc \
    file \
    qemu-user-static

# Install rustup
run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain none -y
run /root/.cargo/bin/rustup toolchain install nightly --allow-downgrade --profile minimal --component rust-src
run /root/.cargo/bin/rustup +nightly add mipsel-unknown-linux-musl

workdir /opt/tinysh
