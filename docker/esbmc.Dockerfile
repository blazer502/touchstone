# ESBMC bounded model checker — prebuilt static binary from upstream release.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG ESBMC_VERSION=v7.6.1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip libgomp1 \
    && curl -fsSL -o /tmp/esbmc.zip \
        "https://github.com/esbmc/esbmc/releases/download/${ESBMC_VERSION}/ESBMC-Linux.zip" \
    && unzip -o /tmp/esbmc.zip -d /opt/esbmc \
    && chmod +x /opt/esbmc/bin/esbmc \
    && ln -s /opt/esbmc/bin/esbmc /usr/local/bin/esbmc \
    && rm -f /tmp/esbmc.zip \
    && rm -rf /var/lib/apt/lists/*

CMD ["esbmc", "--version"]
