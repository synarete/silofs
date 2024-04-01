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

selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
dist_name="$1"
archive_tgz="${dist_name}.tar.gz"
workdir="${selfdir}/${dist_name}"

# Build from source
cd "${selfdir}"
run tar xvfz "${archive_tgz}"
cd "${workdir}"
run ./configure
run make
run make distcheck
run make clean

# Run unitests using developer's flags
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xvfz "${archive_tgz}"
cd "${workdir}"
run ./bootstrap
run make -f devel.mk O=2
run make -f devel.mk O=2 check

# Run clang-scan using developer's flags
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xvfz "${archive_tgz}"
cd "${workdir}"
run ./bootstrap
run make -f devel.mk O=2 clangscan
run make -f devel.mk reset

# Build dist-package
cd "${selfdir}"
run rm -rf "${workdir}"
run tar xvfz "${archive_tgz}"
cd "${workdir}"
run ./dist/packagize.sh

# Post-op cleanup
cd "${selfdir}"
run rm -rf "${workdir}"
msg "${dist_name} passed all checks"



