#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self:" "$@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH


_require_clang_bin() {
  run command -v clang
  run command -v clang++
  run command -v scan-build
}

_setup_clang_env() {
  CCC_ANALYZER_CPLUSPLUS=1
  CCC_CC="$(command -v clang)"
  CCC_CXX="$(command -v clang++)"
  export CCC_ANALYZER_CPLUSPLUS CCC_CC CCC_CXX

}

_clang_analyzer_checkers_args() {
  clang -cc1 -analyzer-checker-help \
    | awk '{print $1}' \
    | grep -Ev 'OVERVIEW|USAGE|CHECKERS' \
    | grep -Ev 'osx|fuchsia|cplusplus|optin|strcpy|webkit' \
    | grep -Ev '^Check|^Warn|^Reports' \
    | grep -Ev 'DeprecatedOrUnsafeBufferHandling' \
    | awk '{print $1}' \
    | sed '/^$/d' \
    | awk '{print " -enable-checker "$1} ' \
    | tr "\n" " "
}

_clang_scan_build() {
  local topdir="$1"
  local builddir="${topdir}/build"
  local outdir="${builddir}/html"
  local analyzer

  cd "${topdir}"
  run mkdir -p "${outdir}"

  cd "${builddir}"
  _setup_clang_env

  analyzer="$(command -v clang)"
  run scan-build \
    --use-analyzer="${analyzer}" \
    ../configure CFLAGS='-O2 -pthread'

  run scan-build \
    --use-analyzer="${analyzer}" \
    -maxloop 64 -k -v -o "${outdir}" \
    $(_clang_analyzer_checkers_args) \
    make all
}

_bootstrap_regen() {
  local topdir="$1"

  "${topdir}"/bootstrap -r
}


# main:
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../)
rootdir=${1:-"${basedir}"}

cd "${rootdir}"
_require_clang_bin
_bootstrap_regen "${rootdir}"
_clang_scan_build "${rootdir}"

# expect scan-build to remove all outputs
outdir="${rootdir}"/build/html
exit_code=$(find "${outdir}" -mindepth 1 -type d | wc -l)
exit ${exit_code}

