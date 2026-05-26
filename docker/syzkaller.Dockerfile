# syzkaller built from source at a pinned commit.
ARG BASE_IMAGE=golang:1.22-bookworm
FROM ${BASE_IMAGE}

ARG SYZKALLER_COMMIT=master
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git make ca-certificates qemu-system-x86 \
    && git clone https://github.com/google/syzkaller /opt/syzkaller \
    && cd /opt/syzkaller && git checkout "${SYZKALLER_COMMIT}" || true \
    && cd /opt/syzkaller && make \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/opt/syzkaller/bin:$PATH
CMD ["syz-manager", "-version"]
