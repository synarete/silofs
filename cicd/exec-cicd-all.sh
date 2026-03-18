#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH
set -o nounset
set -o pipefail

###
self="$(basename "${BASH_SOURCE[0]}")"
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
source "${rootdir}/bash_functions"
commandv make tar timeout

###
sep() { msg "$*" ; echo "# # # # # # # # # # # # # # # # " ; }
exe() { timeout -k 10s 1h runx "$*" ; }

###
if [ "$#" -ne 2 ]; then die "usage: '$self <archive-file> <citests-dir>'"; fi
archive_file="$(realpath "$1")"
citests_dir="$(realpath "$2")"
currdir="$(pwd)"

###
msg "checking input: $*"
cdx "${currdir}"
exe test -f "${archive_file}"
exe mkdir -p "${citests_dir}"
run ls "${citests_dir}"
sep "input OK"

###
msg "prepare workdir: $*"
dist_name="$(basename -s .tar.gz "${archive_file}")"
archive_tgz="${dist_name}.tar.gz"
workdir="${citests_dir}/${dist_name}"
utestsdir="${workdir}/build/test/utests/"
exe mkdir -p "${workdir}"
exe rm -rf "${workdir}"
sep "workdir OK: ${workdir}"

###
msg "build from source: ${archive_file}"
cdx "${currdir}"
exe cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
exe tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "check code style: $(pwd)"
exe ./scripts/checkcodefmt.sh
msg "check build at: $(pwd)"
exe ./configure
exe make
exe make distcheck
exe make clean
cdx "${currdir}"
run rm -rf "${workdir}"
sep "source build OK: ${archive_file}"

###
msg "run developer's checks"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
exe tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "build default mode"
exe make -f devel.mk
exe make -f devel.mk reset
msg "build with analyzer"
exe make -f devel.mk O=0 ANALYZER=1
exe make -f devel.mk reset
msg "run unit-tests"
exe env SILOFS_PANIC_MODE_WAIT=1 make -f devel.mk O=2 check
exe make -f devel.mk reset
sep "developer's build OK"

###
msg "run clang checks"
msg "run clang-scan"
exe make -f devel.mk CC=clang V=1 O=2 scan
exe make -f devel.mk reset
msg "run clang-tidy"
exe make -f devel.mk CC=clang O=2 tidy
exe make -f devel.mk reset
sep "clang checks OK"

###
msg "run sanitizer check"
lsan_suppressions_file="${workdir}/test/utests/lsan_suppressions.txt"
exe make -f devel.mk O=1 SANITIZER=1
exe env ASAN_OPTIONS=detect_leaks=1 \
	LSAN_OPTIONS=suppressions="${lsan_suppressions_file}" \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
exe make -f devel.mk reset
sep "sanitizer OK"

###
msg "run valgrind check"
exe make -f devel.mk
exe valgrind --tool=memcheck --error-exitcode=1 \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
exe make -f devel.mk reset
sep "valgrind OK"

###
cdx "${workdir}"
msg "run heap checker to detect memory leaks"
exe ./bootstrap
exe mkdir -p "${workdir}/build/local/tmp"
cdx "${workdir}/build"
exe ../configure --prefix="${workdir}/build/local" \
	--enable-compile-warnings=error --with-tcmalloc
exe make install
# TODO: fails on ubuntu; why?
exe env HEAPCHECK=normal HEAP_CHECK_TEST_POINTER_ALIGNMENT=1 \
	"${workdir}/build/local/bin/silofs-utests" \
	"${workdir}/build/local/tmp" \
	--malloc --level=2 --silent
cdx "${currdir}"
exe rm -rf "${workdir}"
sep "heapcheck OK"

###
msg "build dist-package"
cdx "${currdir}"
exe cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
exe tar xfz "${archive_tgz}"
cdx "${workdir}"
exe ./dist/packagize.sh
cdx "${currdir}"
exe rm -rf "${workdir}"
sep "dist-package OK"

###
cdx "${currdir}"
run sleep 1
msg "passed all checks for: $* "
