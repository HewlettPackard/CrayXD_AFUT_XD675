FROM ubuntu:25.04

ARG VERSION

LABEL version="$VERSION"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update --allow-releaseinfo-change && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-requests-toolbelt \
    ansible \
    vim \
    git \
    curl \
    ipmitool \
    && apt-get clean

WORKDIR /app

COPY . /app

CMD ["/bin/bash"]
