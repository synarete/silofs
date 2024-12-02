#!/usr/bin/env bash
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
exe() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; exe "$@"; }
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

###
msg "prepare workdir: $*"
dist_name="$(basename -s .tar.gz "${archive_file}")"
archive_tgz="${dist_name}.tar.gz"
workdir="${citests_dir}/${dist_name}"
run mkdir -p "${workdir}"

###
msg "build from source: ${archive_file}"
run cp "${archive_file}" "${citests_dir}"
cdx "${citests_dir}"
run tar xfz "${archive_tgz}"
cdx "${workdir}"
msg "check build at: $(pwd)"
run ./configure
run make
run make check
run make dist
run make distcheck
run make clean

cdx "${currdir}"
run rm -rf "${workdir}"
