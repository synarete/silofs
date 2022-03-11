#!/bin/bash
self=$(basename "${BASH_SOURCE[0]}")
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}/../../")

_msg() { echo "$self: $*" >&2; }
_die() { _msg "$*"; exit 1; }
_try() { ( "$@" ) || _die "failed: $*"; }
_run() { echo "$self: $*" >&2; _try "$@"; }

export LC_ALL=C
unset CDPATH

_usage() {
  echo "${self}" "repodir" "mntdir"
}

_check_args() {
  local repodir="$1"
  local mntdir="$2"

  # [ -d "${repodir}" ] || _die "bad repo dir" "${repodir}"
  [ -d "${mntdir}" ] || _die "bad mount dir" "${mntdir}"
}

_configure_at() {
  local currd
  local workd

  currd="$(realpath "$(pwd)")"
  workd="$(realpath "$1")"

  _run ls "${workd}/configure"
  cd "${workd}" || exit 1
  _run ./configure
  cd "${currd}" || exit 1
}

_silofs_mount_service_status() {
  _run systemctl status silofs-mountd.service > /dev/null
}

_silofs_version() {
  _run command -v silofs
  _run silofs --version
}

_silofs_init() {
  _msg "# Init repositoy: $1"
  _run silofs init "$1"
}

_silofs_mkfs() {
  _msg "# Format file-system: $1"
  _run silofs mkfs -s 32G "$1"
}

_silofs_mount() {
  _msg "# Mount file-system: $1 $2"
  _run silofs mount "$1" "$2"
  _run silofs lsmnt
}

_silofs_umount() {
  _msg "# Un-mount file-system: $1"
  _run silofs umount "$1"
}

_silofs_show_version() {
  _run silofs show version "$1"
}

_silofs_show_repo() {
  _run silofs show repo "$1"
}

_test_simple_io() {
  local testdir="$1"/test_simple_io
  local testfile1="$testdir"/test1
  local testfile2="$testdir"/test2

  _msg "# Test simple I/O"
  _run mkdir "${testdir}"
  _run dd if=/dev/urandom of="${testfile1}" bs=1M count=8
  _run cp "${testfile1}" "${testfile2}"
  _run diff "${testfile1}" "${testfile2}"
  _run mv "${testfile1}" "${testfile2}"
  _run rm "${testfile2}"
  _run rmdir "${testdir}"
}

_test_vfstests() {
  local testdir="$1"/test_vfstests

  _msg "# Test vfstests"
  _run mkdir "${testdir}"
  _run silofs-vfstests "${testdir}"
  _run rmdir "${testdir}"
}

_test_selfcheck() {
  local testdir="$1"/test_selfcheck

  _msg "# Test self-check"
  _run mkdir "${testdir}"
  _run git clone "${basedir}" "${testdir}"
  _run make -C "${testdir}" -f devel.mk check
  _run make -C "${testdir}" -f devel.mk clean
  _run rm -rf "${testdir}"
}

_test_postgresql() {
  local testdir="$1"/test_postgresql
  local pg_git_url="git://git.postgresql.org/git/postgresql.git"

  _msg "# Test postgresql"
  _run mkdir "${testdir}"
  _run git clone "${pg_git_url}" "${testdir}"
  _configure_at "${testdir}"
  _run make -C "${testdir}" all
  _run make -C "${testdir}" check
  _run make -C "${testdir}" clean
  _run rm -rf "${testdir}"
}

_main() {
  local repodir="$1"
  local mntdir="$2"
  local fsname="test"

  _check_args "$@"
  _silofs_version
  _silofs_init "${repodir}"
  _silofs_mkfs "${repodir}/${fsname}"
  _silofs_mount_service_status

  _silofs_mount "${repodir}/${fsname}" "${mntdir}"
  _silofs_show_version "${mntdir}"
  _silofs_show_repo "${mntdir}"
  _test_simple_io "${mntdir}"
  _silofs_umount "${mntdir}"

  _silofs_mount "${repodir}/${fsname}" "${mntdir}"
  _test_vfstests "${mntdir}"
  _test_selfcheck "${mntdir}"
  sleep 1
  _silofs_umount "${mntdir}"

  _silofs_mount "${repodir}/${fsname}" "${mntdir}"
  _test_postgresql "${mntdir}"
  sleep 1
  _silofs_umount "${mntdir}"
}

if [ "$#" -eq 2 ]; then
  _main "$@"
else
  _usage
  exit 1
fi
