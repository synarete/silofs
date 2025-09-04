#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
source "${rootdir}/bash_functions"

# require clang-tidy & bear (generates compilation database for clang tooling)
commandv clang-tidy
commandv bear

# no-fail from here
set -o errexit
set -o nounset
set -o pipefail

# run from project's root dir
cdx "${rootdir}"

# require compilation database
if [ ! -f "${rootdir}/compile_commands.json" ]; then
	run make -f devel.mk reset
	run bear -- make -f devel.mk CC=clang
fi

# run clang-tidy
conf="${rootdir}/.clang-tidy.yaml"
srcs=$(find "${rootdir}/" -type f -name '*.c')
run clang-tidy --config-file="${conf}" ${srcs}
