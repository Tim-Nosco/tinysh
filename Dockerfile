from rust:latest

workdir /root
copy . ./

# trigger downloading all the components specified in the toolchain file
run rustup target list
# download all the musl toolchains we support
run ./scripts/supported_arches.sh download_all_musl_toolchains
