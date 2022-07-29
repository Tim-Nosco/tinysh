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
copy config/buildroot.x86 .config
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
    curl

run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

workdir /opt/tinysh
# $ cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release
