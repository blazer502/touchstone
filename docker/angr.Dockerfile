# angr — pure-pip install on top of slim Python.
ARG BASE_IMAGE=python:3.10-slim
FROM ${BASE_IMAGE}

ARG ANGR_VERSION=9.2.105

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libffi-dev libssl-dev \
    && pip install --no-cache-dir "angr==${ANGR_VERSION}" \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

CMD ["python", "-c", "import angr; print('angr', angr.__version__)"]
