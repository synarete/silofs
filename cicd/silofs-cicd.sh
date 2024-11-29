#!/usr/bin/env bash
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
cdx() { echo "$self: cd $*" >&2; cd "$@" || die "failed: cd $*"; }

###
if [ "$#" -ne 2 ]; then die "usage: '$self <archive-file> <citests-dir>'"; fi
archive_file="$(realpath "$1")"
citests_dir="$(realpath "$2")"
currdir="$(pwd)"

###
msg "checking input: $*"
cdx "${currdir}"
run test -f "${archive_file}"
run mkdir -p "${citests_dir}"
run ls "${citests_dir}"

###
msg "prepare workdir: $*"
dist_name="$(basename -s .tar.gz "${archive_file}")"
archive_tgz="${dist_name}.tar.gz"
workdir="${citests_dir}/${dist_name}"
unitestsdir="${workdir}/build/test/unitests/"
run mkdir -p "${workdir}"
run rm -rf "${workdir}"

###
msg "build from source: ${archive_file}"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "check C-style: $(pwd)"
run ./scripts/sourcedigest.sh > ./srcdigest-pre-fmt
run ./cstylefmt.sh
run ./scripts/sourcedigest.sh > ./srcdigest-post-fmt
run diff -q ./srcdigest-pre-fmt ./srcdigest-post-fmt
run rm -f ./srcdigest-pre-fmt ./srcdigest-post-fmt
msg "check build at: $(pwd)"
run ./configure
run make
run make distcheck
run make clean
cdx "${currdir}"
run rm -rf "${workdir}"

###
msg "run developer's checks"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
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
cdx "${workdir}"
msg "run heap checker to detect memory leaks"
run ./bootstrap
run mkdir -p "${workdir}/build/local/tmp"
cdx "${workdir}/build"
run ../configure --prefix="${workdir}/build/local" \
  --enable-compile-warnings=error --with-tcmalloc
run make install
run env HEAPCHECK=normal HEAP_CHECK_TEST_POINTER_ALIGNMENT=1 \
  "${workdir}/build/local/bin/silofs-unitests" \
  -M -l2 "${workdir}/build/local/tmp"
cdx "${currdir}"
run rm -rf "${workdir}"

###
msg "build dist-package"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
run ./dist/packagize.sh

# Post-op cleanup
msg "post-op cleanup: ${workdir}"
cdx "${currdir}"
run sleep 2
run rm -rf "${workdir}"

###
msg "passed all checks for: $* "
