#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

delim="* * * * * * * * * * * * * * * *"
self=$(basename "${BASH_SOURCE[0]}")

msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; try "$@"; }

selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
dist_name="$1"
archive_tgz="${dist_name}.tar.gz"
workdir="${selfdir}/${dist_name}"
unitestsdir="${workdir}/build/src/tests/unitests/"

# Require sane input
msg "${delim}"
cd "${selfdir}"
run rm -rf "${workdir}"
msg "check using ${archive_tgz}"
run stat "${archive_tgz}"

# Build from (clean) source
msg "${delim}"
cd "${selfdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
msg "check build at: $(pwd)"
run ./cstylefmt.sh
run ./configure
run make
run make distcheck
run make clean

# Run developer's checks
msg "${delim}"
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

# Build dist-package
msg "${delim}"
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
msg "build dist-package at: $(pwd)"
run ./dist/packagize.sh

# Post-op cleanup
msg "${delim}"
cd "${selfdir}"
run rm -rf "${workdir}"
msg "${dist_name} passed all checks"


