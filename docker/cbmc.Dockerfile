# CBMC bounded model checker. Built from upstream deb.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG CBMC_VERSION=6.4.0
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gpg gpg-agent dirmngr \
    && curl -fsSL -o /tmp/cbmc.deb \
        "https://github.com/diffblue/cbmc/releases/download/cbmc-${CBMC_VERSION}/ubuntu-22.04-cbmc-${CBMC_VERSION}-Linux.deb" \
    && apt-get install -y /tmp/cbmc.deb \
    && rm -f /tmp/cbmc.deb \
    && rm -rf /var/lib/apt/lists/*

CMD ["cbmc", "--version"]
