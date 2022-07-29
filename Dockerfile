##################################################################

# Use 12.04 to be consistent with the final release of uClibc
from ubuntu:12.04 as buildroot

# Fix up the apt sources
copy config/sources.list /etc/apt/sources.list

# Prepare dependencies
run apt-get update && apt-get install -y \
	gcc wget make g++ bison flex gettext texinfo \
	patch bzip2 unzip rsync autoconf

# Pull buildroot-2012
workdir /build
copy buildroot/ .
# Use pre-configured settings
copy config/buildroot.mipsel .config
copy config/busybox-1.20.x.config /build/package/busybox/
# Long make
run make -j8

##################################################################

from ubuntu:22.04 as builder

# Copy over the gcc and other build tools
copy --from=0 /build/output/host/ /build/
copy --from=0 /build/output/images/rootfs.tar /build/
run cp -r -n /build/* /

run apt update && apt install -y \
    curl \
    gcc \
    file \
    qemu-user-static

# Install rustup
run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain none -y
run /root/.cargo/bin/rustup toolchain install nightly --allow-downgrade --profile minimal --component rust-src

workdir /opt/tinysh
