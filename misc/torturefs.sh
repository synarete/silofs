#!/bin/bash
#
# Torture file-system using various well-known tools.
#
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

self=$(basename ${BASH_SOURCE[0]})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { echo "$self: $@" >&2; ( "$@" ) || msg "failed: $*"; }
run() { echo "$self: $@" >&2; ( "$@" ) || die "failed: $*"; }

git_clone() {
  url="$1"
  workdir="$2"

  run rm -rf ${workdir}
  run git clone ${url} ${workdir}
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
  local currdir=$(pwd)
  local workdir="$1/coreutils"

  git_clone ${COREUTILS_GIT_GRL} ${workdir}

  cd ${workdir}
  run ./bootstrap
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# GNU tar
do_tar_check() {
  local currdir=$(pwd)
  local workdir="$1/tar"

  git_clone ${TAR_GIT_URL} ${workdir}

  cd ${workdir}
  run ./bootstrap
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# Rsync
do_rsync_check() {
  local currdir=$(pwd)
  local workdir="$1/rsync"

  git_clone ${RSYNC_GIT_URL} ${workdir}

  cd ${workdir}
  run ./configure
  run make
  try make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# Git-SCM
do_gitscm_check() {
  local currdir=$(pwd)
  local workdir="$1/git"

  git_clone ${GITSCM_GIT_URL} ${workdir}

  cd ${workdir}
  run make
  try make test
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# PostgreSQL
do_postgresql_check() {
  local currdir=$(pwd)
  local workdir="$1/postgresql"

  git_clone ${POSTGRESQL_GIT_URL} ${workdir}

  cd ${workdir}
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# Diffutils
do_diffutils_check() {
  local currdir=$(pwd)
  local workdir="$1/diffutils"

  git_clone ${DIFFUTILS_GIT_URL} ${workdir}

  cd ${workdir}
  run ./bootstrap
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# Findutils
do_findutils_check() {
  local currdir=$(pwd)
  local workdir="$1/findutils"

  git_clone ${FINDUTILS_GIT_URL} ${workdir}

  cd ${workdir}
  run ./bootstrap
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# GCC
do_gcc_check() {
  local currdir=$(pwd)
  local workdir="$1/gcc"
  local builddir="$1/gcc-build"

  git_clone ${GCC_GIT_URL} ${workdir}

  run mkdir -p ${workdir}
  cd ${builddir}
  run ${workdir}/configure --enable-languages=c,c++ --disable-multilib
  run make
  run make check

  cd ${workdir}
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${builddir} ${workdir}
}

# Glibc
do_glibc_check() {
  local currdir=$(pwd)
  local workdir="$1/glibc"
  local builddir="$1/glibc-build"

  git_clone ${GLIBC_GIT_URL} ${workdir}

  run mkdir -p ${workdir}
  cd ${builddir}
  run ${workdir}/configure
  run make
  run make check

  cd ${workdir}
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${builddir} ${workdir}
}

# Subversion
do_subversion_check() {
  local currdir=$(pwd)
  local workdir="$1/subversion"

  git_clone ${SUBVERSION_GIT_URL} ${workdir}

  cd ${workdir}
  run ./autogen.sh
  run ./configure
  run make
  run make check
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir}
}

# Sqlite
do_sqlite_check() {
  local currdir=$(pwd)
  local workdir="$1/sqlite"
  local builddir="$1/sqlite-build"

  git_clone ${SQLITE_GIT_URL} ${workdir}
  mkdir -p ${builddir}

  cd ${workdir}
  git log -1 --format=format:%ci%n \
    | sed -e 's/ [-+].*$//;s/ /T/;s/^/D /' > manifest
  echo $(git log -1 --format=format:%H) > manifest.uuid
  cd builddir
  run ../sqlite/configure
  run make
  run make sqlite3.c
  try make test
  git_clean_fxd

  cd ${currdir}
  do_rm_rf ${workdir} ${builddir}
}

# All-in-one
do_all_checks() {
  local workdir=$(realpath "$1")

  do_rsync_check ${workdir}
  do_postgresql_check ${workdir}
  do_coreutils_check ${workdir}
  do_tar_check ${workdir}
  do_diffutils_check ${workdir}
  do_findutils_check ${workdir}
  do_gcc_check ${workdir}
  do_glibc_check ${workdir}
  do_sqlite_check ${workdir}
  do_gitscm_check ${workdir}
  do_subversion_check ${workdir}
}


show_usage() {
  echo ${self}": generate heavy load on file-system via common tools"
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
mkdir -p ${wd}
case "$arg" in
  --coreutils)
    do_coreutils_check ${wd}
    ;;
  --diffutils)
    do_diffutils_check ${wd}
    ;;
  --findutils)
    do_findutils_check ${wd}
    ;;
  --tar)
    do_tar_check ${wd}
    ;;
  --gcc)
    do_gcc_check ${wd}
    ;;
  --glibc)
    do_glibc_check ${wd}
    ;;
  --git)
    do_gitscm_check ${wd}
    ;;
  --rsync)
    do_rsync_check ${wd}
    ;;
  --postgres)
    do_postgresql_check ${wd}
    ;;
  --subversion)
    do_subversion_check ${wd}
    ;;
  --sqlite)
    do_sqlite_check ${wd}
    ;;
  -a|--all)
    do_all_checks ${wd}
    ;;
  *)
    show_usage
    ;;
esac





