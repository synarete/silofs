#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
rootdir=${1:-"${basedir}"}
source "${rootdir}/bash_functions"

# require clang-tools
commandv clang-tidy

# run from project's root dir, no-fail from here
set -o errexit
set -o nounset
set -o pipefail
cdx "${rootdir}"

# run clang-tidy
conf="${rootdir}/.clang-tidy.yaml"
cfiles=$(find "${rootdir}/"{lib,cmd,mntd,test} -type f -name "*.c")
hfiles=$(find "${rootdir}/"{include,lib,cmd,mntd,test} -type f \
	-not -name "fuse_kernel.h" -not -name "config*.h" -name "*.h")
run clang-tidy --config-file="${conf}" ${cfiles} ${hfiles}
