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
run() { echo "$self:" "$@" >&2; try "$@"; }
cdx() { echo "$self: cd $*" >&2; cd "$@" || die "failed: cd $*"; }

# Common variables
name=silofs
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd"

# Prerequisites checks + perpare
try command -v aclocal > /dev/null
try command -v automake > /dev/null
try command -v libtoolize > /dev/null
try command -v rst2man > /dev/null
try command -v rst2html > /dev/null
try command -v basename > /dev/null
run mkdir -p "${workdir}"

# Use autotools build to create dist
autotoolsdir="${workdir}/autotools/"
version_sh="${basedir}"/version.sh
version=$(try "${version_sh}" --version)
distname="${name}-${version}"
disttgz="${distname}.tar.gz"
run mkdir -p "${autotoolsdir}"
cdx "${autotoolsdir}"
run "${basedir}"/bootstrap
run "${basedir}"/configure \
  "--enable-unitests=0" \
  "--enable-compile-warnings=error"
run make dist
run stat "${autotoolsdir}/${disttgz}"

# Run CI tests on local work-dir
run "${selfdir}/silofs-cicd.sh" "${autotoolsdir}/${disttgz}" "${workdir}"

# Post-op cleanups
cdx "${basedir}"
try rm -rf "${autotoolsdir}"
try rm -rf "${workdir}"
run sleep 2

# Goodby ;)
msg "completed successfully for '${version}'"
exit 0
