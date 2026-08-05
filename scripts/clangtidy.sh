#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
rootdir=${1:-"${basedir}"}
conf="${rootdir}/.clang-tidy.yaml"

# shellcheck source=./bash_functions
source "${rootdir}/bash_functions"

# check clang-tools or bail-out
try command -v clang-tidy || exit
try command -v bear || exit

# run from project's root dir, no-fail from here
set -o errexit
set -o nounset
set -o pipefail
cdx "${rootdir}"

# run clang-tidy
_find_src_files() {
	find "${rootdir}/"{lib,cmd,mntd,test} -type f -name "*.c"
}

_find_hdr_files() {
	find "${rootdir}/"{include,lib,cmd,mntd,test} -type f \
		-not -name "fuse_abi*" \
		-not -name "config*.h" \
		-not -name "dirp.h" \
		-not -name "filep.h" \
		-name "*.h"
}

mapfile -t src_files < <(_find_src_files)
mapfile -t hdr_files < <(_find_hdr_files)

run clang-tidy \
    --config-file="${conf}" \
    -p "${rootdir}" \
    -extra-arg=-D_GNU_SOURCE \
    -extra-arg=-D_FILE_OFFSET_BITS=64 \
    "${src_files[@]}" "${hdr_files[@]}"
