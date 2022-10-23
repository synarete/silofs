#!/bin/sh
apt-get install -y \
  gcc \
  clang \
  clang-tools \
  git \
  astyle \
  make \
  automake \
  libtool \
  uuid-dev \
  attr-dev \
  libcap-dev \
  libunwind-dev \
  libgcrypt-dev \
  xxhash \
  libxxhash-dev \
  python3-docutils \
  python3-pygments \
  linux-headers-$(uname -r) \
  pkg-config \
  dpkg-dev \
  debhelper \
  libzstd1 \
  libzstd-dev
