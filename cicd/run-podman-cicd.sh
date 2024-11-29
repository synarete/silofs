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
osflavor=${1:-centos}
name=silofs
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd-${osflavor}"
contfile="Containerfile.${osflavor}"
postscript="${selfdir}/silofs-post-cicd.sh"

# Prerequisites checks + perpare
try command -v aclocal > /dev/null
try command -v automake > /dev/null
try command -v libtoolize > /dev/null
try command -v rst2man > /dev/null
try command -v rst2html > /dev/null
try command -v basename > /dev/null
try command -v podman > /dev/null
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
run cp "${selfdir}/silofs-cicd.sh" "${scratchdir}"
run mv "${autotoolsdir}/${disttgz}" "${scratchdir}"

run podman run --rm \
  --userns keep-id:"uid=$(id -u),gid=$(id -g)" \
  --user="$(id -u):$(id -g)" \
  --volume="/etc/group:/etc/group:ro" \
  --volume="/etc/passwd:/etc/passwd:ro" \
  --volume="/etc/shadow:/etc/shadow:ro" \
  --volume="${scratchdir}:/scratch:rw" \
  --workdir="/scratch" \
  "${imagename}" "./silofs-cicd.sh" "${disttgz}" "/scratch/cicd"

# Remove test image
run podman rmi "${imagename}"

# Post-op cleanups
cdx "${basedir}"
try rm -rf "${autotoolsdir}"
try rm -rf "${scratchdir}"
try rm -rf "${workdir}"
run sleep 2
try "${postscript}" "${basedir}"

# Goodby ;)
msg "completed successfully for '${osflavor}'"
exit 0
