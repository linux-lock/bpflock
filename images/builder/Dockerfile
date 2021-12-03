# SPDX-License-Identifier: Apache-2.0

# Copyright 2021 Djalal Harouni
# Copyright 2020-2021 Authors of Cilium

ARG BASE_RELEASE=$BASE_RELEASE
ARG BASE_IMAGE=$BASE_IMAGE
ARG GOLANG_IMAGE=docker.io/library/golang:1.17.3@sha256:3fa22c4a9f411ebb00f4fef846a7056a37e5397d6f56ae0fdcf65463c09e1ce9
ARG BUILD_IMAGE=docker.io/library/$BASE_IMAGE:$BASE_RELEASE@sha256:7cc0576c7c0ec2384de5cbf245f41567e922aab1b075f3e8ad565f508032df17

FROM ${GOLANG_IMAGE} as golang-dist

FROM ${BUILD_IMAGE} as base-builder

ARG BASE_IMAGE=$BASE_IMAGE
ARG BASE_RELEASE=$BASE_RELEASE
ARG DOCKER_ORG=$DOCKER_ORG
ARG GIT_ORG=$GIT_ORG
ARG ROOT_DIR=$ROOT_DIR
ARG LLVM_VERSION=$LLVM_VERSION
ARG BUILD_DATE=$BUILD_DATE
ARG VCS_REF=$VCS_REF
ARG VCS_BRANCH=$VCS_BRANCH
ARG VERSION=$VERSION

ENV DEBIAN_FRONTEND=noninteractive 
ENV FORCE_BUILD=1

# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

RUN apt update && \
    apt-get upgrade -y --no-install-recommends && \
    apt install -y ca-certificates gpg

RUN echo "deb http://apt.llvm.org/$BASE_RELEASE/ llvm-toolchain-$BASE_RELEASE-$LLVM_VERSION main" >> /etc/apt/sources.list
RUN echo "deb-src http://apt.llvm.org/$BASE_RELEASE/ llvm-toolchain-$BASE_RELEASE-$LLVM_VERSION main" >> /etc/apt/sources.list
RUN apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    apt update -y && \
    apt install -y --no-install-recommends curl wget rsync tar make bash \
    git pkg-config bison binutils-dev build-essential flex libc6-dev clang-$LLVM_VERSION \
    libllvm$LLVM_VERSION llvm-$LLVM_VERSION-dev libclang-$LLVM_VERSION-dev \
    gcc-multilib zlib1g-dev libcap-dev libelf-dev libfl-dev libiberty-dev libbfd-dev

RUN update-ca-certificates && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=golang-dist /usr/local/go /usr/local/go
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

LABEL org.label-schema.name="bpflock-builder" \
    org.label-schema.vendor=$GIT_ORG \
    org.label-schema.descripiton="Builder image for bpflock" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.vcs-url="https://github.com/$GIT_ORG/bpflock" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.version=$VERSION

WORKDIR /go/src/github.com/linux-lock/bpflock