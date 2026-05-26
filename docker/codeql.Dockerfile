# CodeQL CLI — official Linux release bundle.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG CODEQL_VERSION=2.18.4
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip git \
    && curl -fsSL -o /tmp/codeql.zip \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
    && unzip -q /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && git clone --depth 1 https://github.com/github/codeql /opt/codeql-queries \
    && rm -rf /var/lib/apt/lists/*

ENV CODEQL_QUERIES=/opt/codeql-queries
CMD ["codeql", "version"]
