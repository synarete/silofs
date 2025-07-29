#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH
set -o errexit
set -o nounset
set -o pipefail

# Common
name=silofs
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd"
autotoolsdir="${workdir}/autotools/"
version_sh="${basedir}"/version.sh
source "${basedir}/bash_functions"

# Prerequisites checks + prepare
run "${version_sh}"
run mkdir -p "${workdir}"
run mkdir -p "${autotoolsdir}"

# Use autotools build to create dist
version=$("${version_sh}")
version_only=$("${version_sh}" --version)
distname="${name}-${version_only}"
disttgz="${distname}.tar.gz"
cdx "${autotoolsdir}"
run "${basedir}"/bootstrap
run "${basedir}"/configure \
  "--enable-utests=0" \
  "--enable-compile-warnings=error"
run make dist
run stat "${autotoolsdir}/${disttgz}"

# Run CI tests on local work-dir
msg "start running (${version})"
run sh "${selfdir}/exec-cicd-all.sh" \
  "${autotoolsdir}/${disttgz}" "${workdir}"

# Post-op cleanups
cdx "${basedir}"
run rm -rf "${autotoolsdir}"
run rm -rf "${workdir}"
run sleep 2

# Goodby ;)
msg "completed successfully (${version})"
exit 0
