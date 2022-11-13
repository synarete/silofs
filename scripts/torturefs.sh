#!/usr/bin/env bash
# Torture file-system using various well-known tools.
RSYNC_GIT_URL="git://git.samba.org/rsync.git"
POSTGRESQL_GIT_URL="git://git.postgresql.org/git/postgresql.git"
SQLITE_GIT_URL="https://github.com/mackyle/sqlite.git"
COREUTILS_GIT_GRL="https://github.com/coreutils/coreutils"
GITSCM_GIT_URL="https://github.com/git/git.git"
SUBVERSION_GIT_URL="https://github.com/apache/subversion"
DIFFUTILS_GIT_URL="git://git.savannah.gnu.org/diffutils"
FINDUTILS_GIT_URL="git://git.savannah.gnu.org/findutils"
GCC_GIT_URL="https://github.com/gcc-mirror/gcc"
GLIBC_GIT_URL="https://github.com/bminor/glibc"
TAR_GIT_URL="https://git.savannah.gnu.org/git/tar.git"

self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { echo "$self:" "$@" >&2; ( "$@" ) || msg "failed: $*"; }
run() { echo "$self:" "$@" >&2; ( "$@" ) || die "failed: $*"; }

git_clone() {
  url="$1"
  workdir="$2"

  run rm -rf "${workdir}"
  run git clone "${url}" "${workdir}"
}

git_clean_fxd() {
  run git clean -fxd > /dev/null
}

do_rm_rf() {
  for d in "$@"; do
    run rm -rf "${d}"
  done
}

# GNU coreutils
do_coreutils_check() {
  local currdir
  local workdir="$1/coreutils"

  currdir="$(pwd)"
  git_clone ${COREUTILS_GIT_GRL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./bootstrap
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# GNU tar
do_tar_check() {
  local currdir
  local workdir="$1/tar"

  currdir="$(pwd)"
  git_clone ${TAR_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./bootstrap
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# Rsync
do_rsync_check() {
  local currdir
  local workdir="$1/rsync"

  currdir="$(pwd)"
  git_clone ${RSYNC_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# Git-SCM
do_gitscm_check() {
  local currdir
  local workdir="$1/git"

  currdir="$(pwd)"
  git_clone ${GITSCM_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run make
  try make test
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# PostgreSQL
do_postgresql_check() {
  local currdir
  local workdir="$1/postgresql"

  currdir="$(pwd)"
  git_clone ${POSTGRESQL_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# Diffutils
do_diffutils_check() {
  local currdir
  local workdir="$1/diffutils"

  currdir="$(pwd)"
  git_clone ${DIFFUTILS_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./bootstrap
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# Findutils
do_findutils_check() {
  local currdir
  local workdir="$1/findutils"

  currdir="$(pwd)"
  git_clone ${FINDUTILS_GIT_URL} "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./bootstrap
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# GCC
do_gcc_check() {
  local currdir
  local workdir="$1/gcc"
  local builddir="$1/gcc-build"

  currdir="$(pwd)"
  git_clone ${GCC_GIT_URL} "${workdir}"

  run mkdir -p "${workdir}"
  cd "${builddir}" || die "cd ${workdir} failed"
  run "${workdir}"/configure --enable-languages=c,c++ --disable-multilib
  run make
  run make check

  cd "${workdir}" || die "cd ${workdir} failed"
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${builddir}" "${workdir}"
}

# Glibc
do_glibc_check() {
  local currdir
  local workdir="$1/glibc"
  local builddir="$1/glibc-build"

  currdir="$(pwd)"
  git_clone ${GLIBC_GIT_URL} "${workdir}"

  run mkdir -p "${workdir}"
  cd "${builddir}" || die "cd ${builddir} failed"
  run "${workdir}/configure"
  run make
  run make check

  cd "${workdir}" || die "cd ${workdir} failed"
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${builddir}" "${workdir}"
}

# Subversion
do_subversion_check() {
  local currdir
  local workdir="$1/subversion"

  currdir="$(pwd)"
  git_clone "${SUBVERSION_GIT_URL}" "${workdir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  run ./autogen.sh
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}"
}

# Sqlite
do_sqlite_check() {
  local currdir
  local workdir="$1/sqlite"
  local builddir="$1/sqlite-build"

  currdir="$(pwd)"
  git_clone "${SQLITE_GIT_URL}" "${workdir}"
  mkdir -p "${builddir}"

  cd "${workdir}" || die "cd ${workdir} failed"
  git log -1 --format=format:%ci%n \
    | sed -e 's/ [-+].*$//;s/ /T/;s/^/D /' > manifest
  git log -1 --format=format:%H > manifest.uuid
  cd "${builddir}" || die "cd ${builddir} failed"
  run ../sqlite/configure
  run make
  run make sqlite3.c
  try make test
  git_clean_fxd

  cd "${currdir}" || die "cd ${currdir} failed"
  do_rm_rf "${workdir}" "${builddir}"
}

# All-in-one
do_all_checks() {
  local wd

  wd="$(realpath "$1")"
  do_rsync_check "${wd}"
  do_postgresql_check "${wd}"
  do_coreutils_check "${wd}"
  do_tar_check "${wd}"
  do_diffutils_check "${wd}"
  do_findutils_check "${wd}"
  do_gcc_check "${wd}"
  do_glibc_check "${wd}"
  do_sqlite_check "${wd}"
  do_gitscm_check "${wd}"
  do_subversion_check "${wd}"
}


show_usage() {
  echo "${self}: generate heavy load on file-system via common tools"
  echo
  echo "  --coreutils        (${COREUTILS_GIT_GRL})"
  echo "  --diffutils        (${DIFFUTILS_GIT_URL})"
  echo "  --findutils        (${FINDUTILS_GIT_URL})"
  echo "  --tar              (${TAR_GIT_URL})"
  echo "  --gcc              (${GCC_GIT_URL})"
  echo "  --glibc            (${GLIBC_GIT_URL})"
  echo "  --rsync            (${RSYNC_GIT_URL})"
  echo "  --postgres         (${POSTGRESQL_GIT_URL})"
  echo "  --subversion       (${SUBVERSION_GIT_URL})"
  echo "  --sqlite           (${SQLITE_GIT_URL})"
  echo "  --git              (${GITSCM_GIT_URL})"
  echo "  -a|--all"
  echo
}

# Main
arg=${1:-"-a"}
wd=${2:-"$(pwd)"}
mkdir -p "${wd}"
case "$arg" in
  --coreutils)
    do_coreutils_check "${wd}"
    ;;
  --diffutils)
    do_diffutils_check "${wd}"
    ;;
  --findutils)
    do_findutils_check "${wd}"
    ;;
  --tar)
    do_tar_check "${wd}"
    ;;
  --gcc)
    do_gcc_check "${wd}"
    ;;
  --glibc)
    do_glibc_check "${wd}"
    ;;
  --git)
    do_gitscm_check "${wd}"
    ;;
  --rsync)
    do_rsync_check "${wd}"
    ;;
  --postgres)
    do_postgresql_check "${wd}"
    ;;
  --subversion)
    do_subversion_check "${wd}"
    ;;
  --sqlite)
    do_sqlite_check "${wd}"
    ;;
  -a|--all)
    do_all_checks "${wd}"
    ;;
  *)
    show_usage
    ;;
esac





