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
unitestsdir="${workdir}/build/test/unitests/"

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
cd "${selfdir}"
run rm -rf "${workdir}"


###
msg "run developer's checks"
cd "${selfdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
msg "build default mode"
run make -f devel.mk
run make -f devel.mk reset
msg "build with analyzer"
run make -f devel.mk O=0 ANALYZER=1
run make -f devel.mk reset
msg "run unit-tests"
run make -f devel.mk check
run make -f devel.mk reset
msg "run clang-scan"
run make -f devel.mk V=1 O=2 clangscan
run make -f devel.mk reset

###
msg "run sanitizer check"
run make -f devel.mk O=1 SANITIZER=1
run env ASAN_OPTIONS=detect_leaks=1 \
  "${unitestsdir}/silofs-unitests" "${unitestsdir}/ut" -M -l1
run make -f devel.mk reset

###
msg "run valgrind check"
run make -f devel.mk
run valgrind --tool=memcheck --error-exitcode=1 \
  "${unitestsdir}/silofs-unitests" "${unitestsdir}/ut" -M -l1
run make -f devel.mk reset

###
cd "${workdir}"
msg "run heap checker to detect memory leaks"
run ./bootstrap
run mkdir -p "${workdir}/build/local/tmp"
cd "${workdir}/build"
run ../configure --prefix="${workdir}/build/local" \
  --enable-compile-warnings=error --with-tcmalloc
run make install
run env HEAPCHECK=normal HEAP_CHECK_TEST_POINTER_ALIGNMENT=1 \
  "${workdir}/build/local/bin/silofs-unitests" \
  -M -l2 "${workdir}/build/local/tmp"
cd "${selfdir}"
run rm -rf "${workdir}"

###
msg "build dist-package"
cd "${selfdir}"
run tar xfz "${archive_tgz}"
cd "${workdir}"
run ./dist/packagize.sh

# Post-op cleanup
msg "post-op cleanup: ${workdir}"
cd "${selfdir}"
run sleep 2
run rm -rf "${workdir}"

###
msg "passed all checks: ${dist_name} "
