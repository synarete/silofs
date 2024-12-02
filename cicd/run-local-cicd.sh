#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
exe() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self:" "$@" >&2; exe "$@"; }
cdx() { echo "$self: cd $*" >&2; cd "$@" || die "failed: cd $*"; }

# Common variables
name=silofs
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd"
autotoolsdir="${workdir}/autotools/"
version_sh="${basedir}"/version.sh

# Prerequisites checks + prepare
run "${version_sh}"
run mkdir -p "${workdir}"
run mkdir -p "${autotoolsdir}"

# Use autotools build to create dist
version=$("${version_sh}" --version)
distname="${name}-${version}"
disttgz="${distname}.tar.gz"
cdx "${autotoolsdir}"
run "${basedir}"/bootstrap
run "${basedir}"/configure \
  "--enable-unitests=0" \
  "--enable-compile-warnings=error"
run make dist
run stat "${autotoolsdir}/${disttgz}"

# Run CI tests on local work-dir
run "${selfdir}/silofs-cicd-all.sh" "${autotoolsdir}/${disttgz}" "${workdir}"

# Post-op cleanups
cdx "${basedir}"
run rm -rf "${autotoolsdir}"
run rm -rf "${workdir}"
run sleep 2

# Goodby ;)
msg "completed successfully for '${version}'"
exit 0
