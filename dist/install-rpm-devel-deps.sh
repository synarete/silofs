#!/bin/sh
dnf install -y \
  gcc \
  clang \
  clang-analyzer \
  git \
  astyle \
  make \
  autoconf \
  automake \
  libtool \
  libuuid-devel \
  libattr-devel \
  libcap-devel \
  libunwind-devel \
  libgcrypt-devel \
  libzstd-devel \
  xxhash-libs \
  xxhash-devel \
  python3-docutils \
  python3-mypy \
  python3-mypy_extensions \
  python3-pygments \
  python3-pylint \
  kernel-headers \
  rpm-build
