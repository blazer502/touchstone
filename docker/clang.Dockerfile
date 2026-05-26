# Shared clang/LLVM base image. Other tool images derive from this so they
# all see the same compiler. Version pinned via build arg from docs/toolchain.lock.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG LLVM_VERSION=14
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release software-properties-common \
        build-essential cmake ninja-build git python3 python3-pip \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_VERSION} main" \
        > /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        clang-${LLVM_VERSION} clang++-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-tools \
        libclang-${LLVM_VERSION}-dev libclang-rt-${LLVM_VERSION}-dev \
        lld-${LLVM_VERSION} \
    && for t in clang clang++ llvm-config llvm-link llvm-dis llvm-objdump opt; do \
            update-alternatives --install /usr/bin/$t $t /usr/bin/$t-${LLVM_VERSION} 100; \
       done \
    && rm -rf /var/lib/apt/lists/*

CMD ["clang", "--version"]
