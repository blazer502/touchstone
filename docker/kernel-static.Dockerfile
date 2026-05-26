# Smatch + Coccinelle + Sparse — the kernel-idiom-aware Stage A toolset.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG SMATCH_COMMIT=master
ARG COCCINELLE_VERSION=1.1.1
ARG SPARSE_VERSION=0.6.4
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential libsqlite3-dev sqlite3 \
        perl pkg-config libxml2-utils \
        ocaml ocaml-native-compilers ocaml-findlib menhir libmenhir-ocaml-dev \
        libpcre3-dev python3 autoconf automake \
        libgtk-3-dev \
    && git clone https://repo.or.cz/smatch.git /opt/smatch \
    && cd /opt/smatch && git checkout "${SMATCH_COMMIT}" || true \
    && cd /opt/smatch && make && cp smatch /usr/local/bin/ \
    && curl -fsSL "https://github.com/coccinelle/coccinelle/archive/refs/tags/${COCCINELLE_VERSION}.tar.gz" \
        | tar xz -C /opt && mv /opt/coccinelle-${COCCINELLE_VERSION} /opt/coccinelle \
    && cd /opt/coccinelle && ./autogen && ./configure && make && make install \
    && git clone --depth 1 --branch "v${SPARSE_VERSION}" https://git.kernel.org/pub/scm/devel/sparse/sparse.git /opt/sparse \
    && cd /opt/sparse && make PREFIX=/usr/local install \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash", "-c", "smatch --version && spatch --version && sparse --version"]
