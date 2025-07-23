#!/usr/bin/env bash
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
basedir="$(realpath "${selfdir}"/../../)"
workdir="${basedir}/build/dist/img"
autotoolsdir="${workdir}/autotools/"
version_sh="${basedir}"/version.sh
conteng=$(command -v docker || command -v podman || echo "no-docker-or-podman")

# Prerequisites checks + prepare
set -o errexit
set -o nounset
set -o pipefail
run "${version_sh}"
run command -v "${conteng}"
run mkdir -p "${workdir}"
run mkdir -p "${autotoolsdir}"

# Use autotools build to create dist
version=$("${version_sh}" --version)
distname="${name}-${version}"
disttgz="${distname}.tar.gz"
run mkdir -p "${autotoolsdir}"
cdx "${autotoolsdir}"
test -x "${basedir}/configure" || run "${basedir}/bootstrap"
run "${basedir}/configure" \
    "--enable-utests=0" \
    "--enable-compile-warnings=error"
run make dist
run stat "${autotoolsdir}/${disttgz}"

# Extract Containerfile from dist
contfile="Containerfile"
cdx "${workdir}"
run mv "${autotoolsdir}/${disttgz}" "${workdir}"
run tar --extract --to-stdout --file="${disttgz}" \
    "${distname}/dist/img/Containerfile" > "${contfile}"

# Build image using Containerfile and dist tar
imagetag="v${version}"
imagename="${name}:${imagetag}"
cdx "${workdir}"
run "${conteng}" build \
    --tag "${imagename}" \
    --file "${contfile}" \
    --build-arg=DISTNAME="${distname}" \
    "${workdir}"
run "${conteng}" inspect "${imagename}" --format="{{.ID}}"
