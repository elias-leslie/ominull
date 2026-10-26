# Baseline toolchain for the shipped Linux agent (scripts/build-linux-agent.sh).
# The base is pinned by digest there; the agent must load on the oldest
# supported host, so it is built with that host's libbpf, glibc and bpftool.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        gcc libc6-dev clang llvm libbpf-dev libelf-dev zlib1g-dev libcurl4-openssl-dev \
        pkg-config binutils linux-tools-common linux-tools-generic ca-certificates \
    && rm -rf /var/lib/apt/lists/*
