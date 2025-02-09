#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

# run from project's root dir
basedir=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../")
cd "${basedir}"

# require clang-tidy utility
command -v clang-tidy &> /dev/null

# require bear utility to generate compilation database for clang tooling
command -v bear &> /dev/null

# require compilation database
if [ ! -f "${basedir}/compile_commands.json" ]; then
  make -f devel.mk reset
  bear -- make -f devel.mk CC=clang
fi

# run clang-tidy
conf="${basedir}/.clang-tidy.yaml"
srcs=$(find "${basedir}/" -type f -name '*.c')
clang-tidy --config-file="${conf}" ${srcs} 2> /dev/null
