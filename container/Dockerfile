FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

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
    screen expect python3 python3-pip \
    && pip install pytest --break-system-packages \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0
RUN rustup component add rust-src
RUN cargo install cargo-xbuild
RUN rustup target add x86_64-unknown-none

RUN git clone --recursive https://github.com/intel/MigTD.git
