#!/usr/bin/env bash
# Check no source-code change due to style-format by calculating a unique
# sha256 hash-value of project's files before and after running format-scripts.
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
selfdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
rootdir="$(readlink -f "${selfdir}/../")"
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }

_calc_c_sources_hsum() {
  find . -type f -name '*.[ch]' -print \
    | sort -u \
    | xargs sha256sum \
    | sha256sum \
    | awk '{print $1}'
}

_calc_py_sources_hsum() {
  find . -type f -name '*.py' -print \
    | sort -u \
    | xargs sha256sum \
    | sha256sum \
    | awk '{print $1}'
}

_exec_c_code_fmt() {
  ./cstylefmt.sh
}

_exec_py_code_fmt() {
  ./py/pycheck.sh ./py/qatests &> /dev/null
}

cd "${rootdir}"
hsum_pre="$(_calc_c_sources_hsum)"
_exec_c_code_fmt
hsum_post="$(_calc_c_sources_hsum)"
[[ "$hsum_pre" == "$hsum_post" ]] || die "C code formatted"

cd "${rootdir}"
hsum_pre="$(_calc_py_sources_hsum)"
_exec_py_code_fmt
hsum_post="$(_calc_py_sources_hsum)"
[[ "$hsum_pre" == "$hsum_post" ]] || die "Python code formatted"
