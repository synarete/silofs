#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../)
rootdir=${1:-"${basedir}"}
outdir="${rootdir}"/build/html


# run-and-log helpers
_msg() { echo "$self: $*" >&2; }
_die() { _msg "$*"; exit 1; }
_try() { ( "$@" ) || _die "failed: $*"; }
_run() { echo "$self:" "$@" >&2; _try "$@"; }


_clang_scan_enabled_checkers_args() {
  clang -cc1 -analyzer-checker-help \
    | awk '{print $1}' \
    | grep -Ev 'OVERVIEW|USAGE|CHECKERS' \
    | grep -Ev 'osx|fuchsia|cplusplus|optin|strcpy|webkit' \
    | grep -Ev '^Check|^Warn|^Reports' \
    | grep -Ev 'DeprecatedOrUnsafeBufferHandling' \
    | awk '{print $1}' \
    | sed '/^$/d' \
    | awk '{print " -enable-checker "$1""} '
}

_clang_requires() {
  command -v clang
  command -v clang++
  command -v scan-build
}

_clang_scan_env() {
  CCC_CC="$(command -v clang)"
  CCC_CXX="$(command -v clang++)"
  CCC_ANALYZER_CPLUSPLUS=1
  export CCC_CC CCC_CXX CCC_ANALYZER_CPLUSPLUS
}

_clang_scan_build() {
  local topdir="$1"
  local builddir="${topdir}/build"
  local outdir="${builddir}/html"

  cd "${topdir}"
  mkdir -p "${outdir}"

  cd "${builddir}"
  _clang_scan_env

  _run scan-build \
    --use-cc="${CCC_CC}" \
    --use-c++="${CCC_CXX}" \
    ../configure CFLAGS='-O2 -pthread'

  _run scan-build \
    --use-cc="${CCC_CC}" \
    --use-c++="${CCC_CXX}" \
    -maxloop 32 -k -v -o "${outdir}" \
    $(_clang_scan_enabled_checkers_args) \
    make all
}

_rebootstrap() {
  _run "${1}"/bootstrap -r
}


# main:
cd "${rootdir}"
_clang_requires
_rebootstrap "${rootdir}"
_clang_scan_build "${rootdir}"

# expect scan-build to remove all outputs
exit_code=$(find "${outdir}" -mindepth 1 -type d | wc -l)
exit "${exit_code}"

