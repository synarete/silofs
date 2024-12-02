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
osflavor=${1:-centos}
contfile="Containerfile.${osflavor}"
name=silofs
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd-${osflavor}"
autotoolsdir="${workdir}/autotools/"
version_sh="${basedir}"/version.sh

# Prerequisites checks + prepare
run "${version_sh}"
run command -v podman
run mkdir -p "${workdir}"
run mkdir -p "${autotoolsdir}"

# Use autotools build to create dist
version=$("${version_sh}" --version)
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

# Build image using Containerfile and installation scripts
imagesdir="${workdir}/images/"
imagetag="v${version}"
imagename="${name}-cicd-${osflavor}:${imagetag}"
run mkdir -p "${imagesdir}"
run cp "${basedir}/dist/rpm/install-rpm-deps.sh" "${imagesdir}"
run cp "${basedir}/dist/deb/install-deb-deps.sh" "${imagesdir}"
run cp "${selfdir}/${contfile}" "${imagesdir}"

cdx "${imagesdir}"
run podman build \
  --tag "${imagename}" --file "${imagesdir}/${contfile}" "${imagesdir}"
run podman inspect "${imagename}"

# Run CI build-and-test cycle using local user and scratch dir
scratchdir="${workdir}/scratch/"
run mkdir -p "${scratchdir}"
run cp "${selfdir}/silofs-cicd-build.sh" "${scratchdir}"
run mv "${autotoolsdir}/${disttgz}" "${scratchdir}"

run podman run --rm \
  --userns keep-id:"uid=$(id -u),gid=$(id -g)" \
  --user="$(id -u):$(id -g)" \
  --volume="/etc/group:/etc/group:ro" \
  --volume="/etc/passwd:/etc/passwd:ro" \
  --volume="/etc/shadow:/etc/shadow:ro" \
  --volume="${scratchdir}:/scratch:rw" \
  --workdir="/scratch" \
  "${imagename}" "./silofs-cicd-build.sh" "${disttgz}" "/scratch/cicd"

# Remove test image
run podman rmi "${imagename}"

# Post-op cleanups
cdx "${basedir}"
run rm -rf "${autotoolsdir}"
run rm -rf "${scratchdir}"
run rm -rf "${workdir}"

# Goodby ;)
msg "completed successfully for '${osflavor}'"
exit 0
