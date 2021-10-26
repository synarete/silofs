#!/bin/bash
#
# helper script to install dependencies on local machine, prior to build,
# either for redhat or debian based systems. Run as privileged user.
#
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self:" "$@" >&2; try "$@"; }

install_deb() {
  run apt-get install -y \
    gcc \
    clang \
    clang-tools \
    git \
    gitlint \
    astyle \
    make \
    automake \
    libtool \
    uuid-dev \
    attr-dev \
    libcap-dev \
    libunwind-dev \
    libgcrypt-dev \
    python3-docutils \
    python3-pygments \
    linux-headers-$(uname-r) \
    pkg-config \
    dpkg-dev \
    debhelper
}

install_rpm() {
  run dnf install -y \
    gcc \
    clang \
    clang-analyzer \
    git \
    gitlint \
    astyle \
    make \
    automake \
    libtool \
    libuuid-devel \
    libattr-devel \
    libcap-devel \
    libunwind-devel \
    libgcrypt-devel \
    python3-docutils \
    python3-pygments \
    kernel-headers \
    rpm-build
}

if [[ -f '/etc/redhat-release' ]]; then
  install_rpm
elif [[ -f '/etc/debian_version' ]]; then
  install_deb
else
  die "unknown packaging manager"
fi

