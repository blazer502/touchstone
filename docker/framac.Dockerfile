# Frama-C with EVA plugin. Installed via opam (the upstream-supported path).
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG FRAMAC_VERSION=29.0
ENV DEBIAN_FRONTEND=noninteractive
ENV OPAMROOT=/root/.opam OPAMYES=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential m4 unzip rsync \
        opam pkg-config libgmp-dev libgtk-3-dev libcairo2-dev \
        libgtksourceview-3.0-dev autoconf time \
    && opam init --bare --disable-sandboxing \
    && opam switch create 4.14.1 \
    && eval "$(opam env)" \
    && opam install -y "frama-c.${FRAMAC_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/root/.opam/4.14.1/bin:$PATH
CMD ["frama-c", "-version"]
