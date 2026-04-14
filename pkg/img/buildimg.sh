#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../../)"
source "${rootdir}/bash_functions"

# Common variables
name=silofs
workdir="${rootdir}/build/pkg/img"
autotoolsdir="${workdir}/autotools/"
version_sh="${rootdir}"/version.sh
conteng=$(command -v docker || command -v podman || echo "no-docker-or-podman")

# Prerequisites checks + prepare
set -o errexit
set -o nounset
set -o pipefail
run "${version_sh}"
commandv "${conteng}"
run mkdir -p "${workdir}"
run mkdir -p "${autotoolsdir}"

# Use autotools build to create dist
version=$("${version_sh}" --version)
distname="${name}-${version}"
disttgz="${distname}.tar.gz"
run mkdir -p "${autotoolsdir}"
cdx "${autotoolsdir}"
test -x "${rootdir}/configure" || run "${rootdir}/bootstrap"
run "${rootdir}/configure" \
	"--enable-utests=0" \
	"--enable-compile-warnings=error"
run make dist
run stat -c "%s" "${autotoolsdir}/${disttgz}"

# Extract Containerfile from dist
contfile="Containerfile"
cdx "${workdir}"
run mv "${autotoolsdir}/${disttgz}" "${workdir}"
run tar --extract --to-command="tee ${contfile}" \
	--file="${disttgz}" "${distname}/pkg/img/Containerfile"

# Build image using Containerfile and dist tar
imagetag=${SILOFS_IMAGETAG:-"v${version}"}
imagename=${SILOFS_IMAGENAME:-"${name}:${imagetag}"}
cdx "${workdir}"
run "${conteng}" build \
	--force-rm \
	--tag "${imagename}" \
	--file "${contfile}" \
	--build-arg=DISTNAME="${distname}" \
	"${workdir}"

# Post build cleanup
run "${conteng}" image prune -f

# Inspect final image
run "${conteng}" inspect "${imagename}" --format="{{.ID}}"
