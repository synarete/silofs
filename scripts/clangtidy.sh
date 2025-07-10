#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
exe() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self:" "$@" >&2; exe "$@"; }
cdx() { echo "$self: cd $*" >&2; cd "$@" || die "failed: cd $*"; }

# require clang-tidy & bear (generates compilation database for clang tooling)
command -v clang-tidy $> /dev/null || { msg "cant find 'clang-tidy'"; exit ; }
command -v bear $> /dev/null || { msg "cant find 'bear'"; exit ; }

# no-fail from here
set -o errexit
set -o nounset
set -o pipefail

# run from project's root dir
basedir=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../")
cdx "${basedir}"

# require compilation database
if [ ! -f "${basedir}/compile_commands.json" ]; then
  run make -f devel.mk reset
  run bear -- make -f devel.mk CC=clang
fi

# run clang-tidy
conf="${basedir}/.clang-tidy.yaml"
srcs=$(find "${basedir}/" -type f -name '*.c')
run clang-tidy --config-file="${conf}" ${srcs}
