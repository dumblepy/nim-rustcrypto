FROM ubuntu:26.04

# prevent timezone dialogue
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt upgrade -y && \
    apt install -y \
        build-essential \
        # build blst for wasm
        clang \
        curl \
        git

# rust
WORKDIR /root
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH $PATH:/root/.cargo/bin

# nim
WORKDIR /root
RUN curl https://nim-lang.org/choosenim/init.sh -o init.sh
RUN sh init.sh -y
RUN rm -f init.sh
ENV PATH $PATH:/root/.nimble/bin

# node
# https://nodejs.org/en/download/prebuilt-binaries
ARG NODE_VERSION=24.22.1
RUN curl -OL https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz
RUN tar -xvf node-v${NODE_VERSION}-linux-x64.tar.xz
RUN rm node-v${NODE_VERSION}-linux-x64.tar.xz
RUN mv node-v${NODE_VERSION}-linux-x64 .node
ENV PATH $PATH:/root/.node/bin

# circom (always latest stable release)
# https://github.com/iden3/circom/releases/latest
# Docker may reuse a cached download; run `docker compose build --no-cache`
# when you need to force a refresh to the latest release.
RUN curl -fsSL -o /usr/local/bin/circom \
        https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 && \
    chmod +x /usr/local/bin/circom && \
    circom --version

# snarkjs (circom proof toolchain)
ARG SNARKJS_VERSION=0.7.6
RUN npm install -g --no-fund --no-audit snarkjs@${SNARKJS_VERSION}


RUN git config --global --add safe.directory /application
WORKDIR /application
