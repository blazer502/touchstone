# SVF — LLVM-based pointer analysis / value flow. Built on top of our shared clang image.
ARG LLVM_VERSION=14
FROM touchstone/clang:${LLVM_VERSION}

ARG SVF_VERSION=2.8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        zip unzip libz-dev libtinfo-dev zlib1g-dev \
    && git clone --depth 1 --branch "SVF-${SVF_VERSION}" https://github.com/SVF-tools/SVF /opt/svf \
    && cd /opt/svf && bash ./build.sh \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/opt/svf/Release-build/bin:$PATH
ENV SVF_DIR=/opt/svf
CMD ["wpa", "--version"]
