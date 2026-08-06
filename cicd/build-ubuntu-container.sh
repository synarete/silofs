#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
buildd="build"
builddir="${rootdir}/${buildd}"
version_sh=${rootdir}/version.sh

source "${rootdir}/bash_functions"
commandv podman
version=$(run "${version_sh}" --version)
tagname="silofs-ubuntu:${version}"

cdx "${rootdir}"
run cp "${rootdir}/pkg/deb/install-deb-deps.sh" "${builddir}"
run make -f devel.mk dist
run podman build \
	--build-arg=DISTNAME="silofs-${version}" \
	--build-arg=BUILDDIR="${buildd}" \
	--file "${selfdir}/Containerfile" \
	--tag "${tagname}" .
