#!/bin/sh
dnf install -y \
  gcc \
  make \
  automake \
  libtool \
  libuuid-devel \
  libattr-devel \
  libcap-devel \
  libunwind-devel \
  libgcrypt-devel \
  xxhash-libs \
  xxhash-devel \
  python3-docutils \
  rpm-build

