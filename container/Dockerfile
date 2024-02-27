FROM ubuntu:22.04@sha256:f9d633ff6640178c2d0525017174a688e2c1aef28f0a0130b26bd5554491f0da

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
WORKDIR /root

# Install all required packages in one go to optimize the image
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# DEBIAN_FRONTEND is set for tzdata.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential unzip ca-certificates curl gcc git libssl-dev pkg-config ssh \
    clang llvm nasm \
    ocaml ocamlbuild wget pkg-config libtool autoconf autotools-dev automake \
    screen expect \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2023-12-31
RUN rustup component add rust-src
RUN cargo install cargo-xbuild

RUN git clone --recursive https://github.com/intel/MigTD.git
