# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Djalal Harouni

ARG DOCKER_ORG=$DOCKER_ORG
ARG BASE_IMAGE=$BASE_IMAGE
ARG BASE_RELEASE=$BASE_RELEASE
ARG RUNTIME_IMAGE=docker.io/library/$BASE_IMAGE:$BASE_RELEASE@sha256:7cc0576c7c0ec2384de5cbf245f41567e922aab1b075f3e8ad565f508032df17
ARG BUILDER_IMAGE=docker.io/$DOCKER_ORG/bpflock-builder:latest

FROM $BUILDER_IMAGE as bpflock-builder

ARG BASE_IMAGE=$BASE_IMAGE
ARG DOCKER_ORG=$DOCKER_ORG
ARG GIT_ORG=$GIT_ORG
ARG ROOT_DIR=$ROOT_DIR
ARG LLVM_VERSION=$LLVM_VERSION
ARG VERSION=$VERSION

# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

RUN apt update -y && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean

ENV DOCKER_ORG=$DOCKER_ORG
ENV GIT_ORG=$GIT_ORG
ENV BASE_IMAGE=$BASE_IMAGE
ENV BASE_RELEASE=$BASE_RELEASE
ENV ROOT_DIR=$ROOT_DIR
ENV LLVM_VERSION=$LLVM_VERSION

WORKDIR /go/src/github.com/linux-lock/bpflock

COPY . .

# Make bpf tools and bpflock daemon
RUN make container-bpf-tools
RUN make bpflock-daemon

# Generate runtime image
FROM $RUNTIME_IMAGE as runtime

ARG DOCKER_ORG=$DOCKER_ORG
ARG GIT_ORG=$GIT_ORG
ARG BUILD_DATE=$BUILD_DATE
ARG VCS_REF=$VCS_REF
ARG VCS_BRANCH=$VCS_BRANCH
ARG VERSION=$VERSION

ARG TARGETARCH

RUN mkdir -p /usr/lib/bpflock/ && mkdir -p /etc/bpflock/bpflock.d && mkdir -p /etc/bpflock/bpf.d

# Copy configuration
COPY --from=bpflock-builder /go/src/github.com/linux-lock/bpflock/deploy/configs/bpflock/* /etc/bpflock/

# Install generated programs
COPY --from=bpflock-builder /go/src/github.com/linux-lock/bpflock/build/dist/bin/bpflock /usr/lib/bpflock/
COPY --from=bpflock-builder /go/src/github.com/linux-lock/bpflock/build/dist/bin/bpf /usr/lib/bpflock/bpf

# Install bpftool and tools
COPY --from=bpflock-builder /go/src/github.com/linux-lock/bpflock/tools/$TARGETARCH/bpftool /usr/lib/bpflock/

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y --no-install-recommends binutils \
    libcap2 libelf1 curl wget bash && \
    apt-get clean

RUN apt-get update && apt-get install -y ca-certificates && \
    update-ca-certificates && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

LABEL org.label-schema.name="bpflock" \
    org.label-schema.vendor=$GIT_ORG \
    org.label-schema.descripiton="bpflock - eBPF driven security for locking and auditing Linux machines" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.vcs-url="https://github.com/$GIT_ORG/bpflock" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.version=$VERSION

CMD ["/usr/lib/bpflock/bpflock"]
