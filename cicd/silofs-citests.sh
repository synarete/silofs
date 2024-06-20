#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; try "$@"; }
xrun() { echo "$self: $*" >&2; ( "$@" ) || true; }

selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
dist_name="$1"
archive_tgz="${dist_name}.tar.gz"
workdir="${selfdir}/${dist_name}"
unitestsdir="${workdir}/build/src/test/unitests/"

###
msg "cheching input: ${archive_tgz}"
cd "${selfdir}"
run rm -rf "${workdir}"
run stat "${archive_tgz}"

###
msg "build from source: ${archive_tgz}"
cd "${selfdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
msg "check build at: $(pwd)"
run ./cstylefmt.sh
run ./configure
run make
run make distcheck
run make clean

###
msg "run developer's checks"
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
msg "run unit-tests"
run make -f devel.mk reset
run make -f devel.mk O=2
run make -f devel.mk O=2 check
msg "run gcc-analyzer"
run make -f devel.mk reset
run make -f devel.mk O=0 CC=gcc ANALYZER=1
msg "run clang-scan"
run make -f devel.mk reset
run make -f devel.mk V=1 O=2 clangscan
msg "run valgrind check"
run make -f devel.mk reset
run make -f devel.mk
run valgrind --tool=memcheck --error-exitcode=1 \
  "${unitestsdir}/silofs-unitests" "${unitestsdir}/ut" -M -l1

###
msg "build dist-package"
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
run ./dist/packagize.sh

# Post-op cleanup
msg "post-op cleanup: ${workdir}"
cd "${selfdir}"
run sleep 1
xrun killall catatonit # some leftovers on debian
run sleep 1
run rm -rf "${workdir}"

###
msg "passed all checks: ${dist_name} "


