#!/bin/bash

base_deps=(
  attr-dev
  automake
  cdbs
  clang
  clang-tools
  debhelper
  dpkg-dev
  gcc
  libcap-dev
  libgcrypt-dev
  libtool
  libunwind-dev
  libxxhash-dev
  libzstd1
  libzstd-dev
  make
  pkg-config
  pylint
  python3-docutils
  python3-flake8
  python3-flake8-builtins
  python3-flake8-import-order
  python3-mypy
  python3-mypy-extensions
  python3-pydantic
  python3-setproctitle
  python3-toml
  uuid-dev
  xxhash
)

citests_deps=(
  gcc
  git
  make
  automake
  libtool
  fio
  flex
  bison
  libcap-dev
  libunwind-dev
  libreadline-dev
  zlib1g-dev
  libssl-dev
  libcurl4-openssl-dev
  libexpat1-dev
)

extra_deps=(
  astyle
  black
  flake8
  gdb
  git
  gitlint
  mypy
  pylint
  python3-pathspec
  python3-pygments
  python3-typeshed
)

_install_deb_pkgs() {
  apt-get install -y "$@"
}

arg=${1:-}
case "$arg" in
  -a|--all)
    _install_deb_pkgs "${base_deps[@]}" "${citests_deps[@]}" "${extra_deps[@]}"
    ;;
  -b|--base)
    _install_deb_pkgs "${base_deps[@]}"
    ;;
  -c|--citests)
    _install_deb_pkgs "${citests_deps[@]}"
    ;;
  -e|--extra)
    _install_deb_pkgs "${extra_deps[@]}"
    ;;
  *)
    _install_deb_pkgs "${base_deps[@]}"
    ;;
esac

