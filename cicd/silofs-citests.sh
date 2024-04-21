#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

delim=". . . . . . . . . . . . . . . ."
self=$(basename "${BASH_SOURCE[0]}")

msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; try "$@"; }

selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
dist_name="$1"
archive_tgz="${dist_name}.tar.gz"
workdir="${selfdir}/${dist_name}"

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
msg "run unit-tests at: $(pwd)"
run make -f devel.mk reset
run make -f devel.mk O=2
run make -f devel.mk O=2 check
msg "run gcc-analyzer at: $(pwd)"
run make -f devel.mk reset
run make -f devel.mk O=0 CC=gcc ANALYZER=1
msg "run clang-scan at: $(pwd)"
run make -f devel.mk reset
run make -f devel.mk V=1 O=2 clangscan

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


