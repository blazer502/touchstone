# S2E — selective symbolic execution on QEMU. Upstream provides s2e-env tool that
# bootstraps a full S2E checkout/build. We just install s2e-env here; full provisioning
# (which fetches QEMU, KLEE, libs2e, and builds them) is deferred to the s2e-env init
# step run from this container as needed.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG S2E_VERSION=2.0.0
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git python3 python3-pip python3-venv \
        build-essential \
    && python3 -m pip install --no-cache-dir s2e-env \
    && rm -rf /var/lib/apt/lists/*

CMD ["s2e", "--help"]
