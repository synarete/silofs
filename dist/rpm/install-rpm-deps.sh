#!/bin/bash

base_deps=(
  autoconf
  automake
  gcc
  libtool
  libattr-devel
  libcap-devel
  libubsan
  libunwind-devel
  libuuid-devel
  libgcrypt-devel
  libzstd-devel
  make
  python3-docutils
  python3-pydantic
  python3-toml
  python3-typing-extensions
  rpm-build
  xxhash-libs
  xxhash-devel
)

qatests_deps=(
  automake
  bison
  expat-devel
  fio
  flex
  gcc
  git
  git-email
  libattr-devel
  libcap-devel
  libcurl-devel
  libtool
  libunwind-devel
  libuuid-devel
  lz4
  lz4-devel
  openssl-devel
  perl-core
  perl-libwww-perl
  python3-setproctitle
  readline-devel
  zlib
  zlib-devel
)

extra_deps=(
  astyle
  clang
  clang-analyzer
  clang-libs
  clang-tools-extra
  gdb
  git
  python3-docutils
  python3-flake8
  python3-flake8-import-order
  python3-flake8-builtins
  python3-mypy
  python3-mypy_extensions
  python3-pygments
  python3-pylint
  python3-setproctitle
)

_install_rpm_pkgs() {
  dnf install -y "$@"
}

arg=${1:-}
case "$arg" in
  -a|--all)
    _install_rpm_pkgs "${base_deps[@]}" "${qatests_deps[@]}" "${extra_deps[@]}"
    ;;
  -b|--base)
    _install_rpm_pkgs "${base_deps[@]}"
    ;;
  -c|--qatests)
    _install_rpm_pkgs "${qatests_deps[@]}"
    ;;
  -e|--extra)
    _install_rpm_pkgs "${extra_deps[@]}"
    ;;
  *)
    _install_rpm_pkgs "${base_deps[@]}"
    ;;
esac

