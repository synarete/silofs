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
runx test -f "${archive_file}"
runx mkdir -p "${citests_dir}"
run ls "${citests_dir}"
sep "input OK"

###
msg "prepare workdir: $*"
dist_name="$(basename -s .tar.gz "${archive_file}")"
archive_tgz="${dist_name}.tar.gz"
workdir="${citests_dir}/${dist_name}"
utestsdir="${workdir}/build/test/utests/"
runx mkdir -p "${workdir}"
runx rm -rf "${workdir}"
sep "workdir OK: ${workdir}"

###
msg "build from source: ${archive_file}"
cdx "${currdir}"
runx cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
runx tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "check code style: $(pwd)"
runx ./scripts/checkcodefmt.sh
msg "check build at: $(pwd)"
runx ./configure
runx make
runx make distcheck
runx make clean
cdx "${currdir}"
run rm -rf "${workdir}"
sep "source build OK: ${archive_file}"

###
msg "run developer's checks"
cdx "${currdir}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
runx tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "build default mode"
runx make -f devel.mk
runx make -f devel.mk reset
msg "build with analyzer"
runx make -f devel.mk O=0 ANALYZER=1
runx make -f devel.mk reset
msg "run unit-tests"
runx env SILOFS_PANIC_MODE_WAIT=1 make -f devel.mk check
runx make -f devel.mk reset
msg "run clang-scan"
runx make -f devel.mk CC=clang V=1 O=2 scan
runx make -f devel.mk reset
sep "developer's build OK"

###
msg "run clang-tidy"
runx make -f devel.mk CC=clang O=2 tidy
runx make -f devel.mk reset
sep "clang-tidy OK"

###
msg "run sanitizer check"
lsan_suppressions_file="${workdir}/test/utests/lsan_suppressions.txt"
runx make -f devel.mk O=1 SANITIZER=1
runx env ASAN_OPTIONS=detect_leaks=1 \
	LSAN_OPTIONS=suppressions="${lsan_suppressions_file}" \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
runx make -f devel.mk reset
sep "sanitizer OK"

###
msg "run valgrind check"
runx make -f devel.mk
runx valgrind --tool=memcheck --error-exitcode=1 \
	"${utestsdir}/silofs-utests" "${utestsdir}/ut" \
	--malloc --level=1 --silent
runx make -f devel.mk reset
sep "valgrind OK"

###
cdx "${workdir}"
msg "run heap checker to detect memory leaks"
runx ./bootstrap
runx mkdir -p "${workdir}/build/local/tmp"
cdx "${workdir}/build"
runx ../configure --prefix="${workdir}/build/local" \
	--enable-compile-warnings=error --with-tcmalloc
runx make install
# TODO: fails on ubuntu; why?
runx env HEAPCHECK=normal HEAP_CHECK_TEST_POINTER_ALIGNMENT=1 \
	"${workdir}/build/local/bin/silofs-utests" \
	"${workdir}/build/local/tmp" \
	--malloc --level=2 --silent
cdx "${currdir}"
runx rm -rf "${workdir}"
sep "heapcheck OK"

###
msg "build dist-package"
cdx "${currdir}"
runx cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
runx tar xfz "${archive_tgz}"
cdx "${workdir}"
runx ./dist/packagize.sh
cdx "${currdir}"
runx rm -rf "${workdir}"
sep "dist-package OK"

###
cdx "${currdir}"
run sleep 1
msg "passed all checks for: $* "
