# SymCC — compile-time concolic instrumentation over our shared clang.
ARG LLVM_VERSION=14
FROM veri-agent/clang:${LLVM_VERSION}

ARG SYMCC_COMMIT=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        z3 libz3-dev python3 python3-pip libgmp-dev \
    && git clone --recursive https://github.com/eurecom-s3/symcc /opt/symcc \
    && cd /opt/symcc && git checkout "${SYMCC_COMMIT}" || true \
    && cd /opt/symcc && mkdir build && cd build \
    && cmake -G Ninja -DQSYM_BACKEND=ON -DZ3_TRUST_SYSTEM_VERSION=ON .. \
    && ninja \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/opt/symcc/build:$PATH
CMD ["symcc", "--version"]
