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
sep() { msg "$*" ; echo "# # # # # # # # # # # # # # # # " ; }

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
sep "input OK"

###
msg "prepare workdir: $*"
dist_name="$(basename -s .tar.gz "${archive_file}")"
archive_tgz="${dist_name}.tar.gz"
workdir="${citests_dir}/${dist_name}"
utestsdir="${workdir}/build/test/utests/"
run mkdir -p "${workdir}"
run rm -rf "${workdir}"
sep "workdir OK: ${workdir}"

###
msg "build from source: ${archive_file}"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "check code style: $(pwd)"
run ./scripts/checkcodefmt.sh
msg "check build at: $(pwd)"
run ./configure
run make
run make distcheck
run make clean
cdx "${currdir}"
run rm -rf "${workdir}"
sep "source build OK: ${archive_file}"

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
run env SILOFS_PANIC_MODE_WAIT=1 make -f devel.mk check
run make -f devel.mk reset
msg "run clang-scan"
run make -f devel.mk CC=clang V=1 O=2 scan
run make -f devel.mk reset
sep "developer's build OK"

###
msg "run clang-tidy"
run make -f devel.mk CC=clang O=2 tidy
run make -f devel.mk reset
sep "clang-tidy OK"

###
msg "run sanitizer check"
lsan_suppressions_file="${workdir}/test/utests/lsan_suppressions.txt"
run make -f devel.mk O=1 SANITIZER=1
run env ASAN_OPTIONS=detect_leaks=1 \
	LSAN_OPTIONS=suppressions="${lsan_suppressions_file}" \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
run make -f devel.mk reset
sep "sanitizer OK"

###
msg "run valgrind check"
run make -f devel.mk
run valgrind --tool=memcheck --error-exitcode=1 \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
run make -f devel.mk reset
sep "valgrind OK"

###
cdx "${workdir}"
msg "run heap checker to detect memory leaks"
run ./bootstrap
run mkdir -p "${workdir}/build/local/tmp"
cdx "${workdir}/build"
run ../configure --prefix="${workdir}/build/local" \
	--enable-compile-warnings=error --with-tcmalloc
run make install
# TODO: fails on ubuntu; why?
run env HEAPCHECK=normal HEAP_CHECK_TEST_POINTER_ALIGNMENT=1 \
	"${workdir}/build/local/bin/silofs-utests" \
	"${workdir}/build/local/tmp" \
	--malloc --level=2 --silent
cdx "${currdir}"
run rm -rf "${workdir}"
sep "heapcheck OK"

###
msg "build dist-package"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
run ./dist/packagize.sh
cdx "${currdir}"
run rm -rf "${workdir}"
sep "dist-package OK"

###
cdx "${currdir}"
run sleep 1
msg "passed all checks for: $* "
