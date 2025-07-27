#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
pre() { echo "$self:${BASH_LINENO[1]}: $*" >&2; }
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
exe() { ( "$@" ) || die "failed: $*"; }
run() { pre "$@"; exe "$@"; }
cdx() { pre "cd $*"; cd "$@" || die "failed: cd $*"; }

# Do nothing if podman is missing
command -v podman > /dev/null || exit 0

# Common variables
name=silofs
selfpid="$$"
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
basedir="$(realpath "${selfdir}"/../)"
workdir="${basedir}/build/cicd/"
version_sh="${basedir}"/version.sh

# Prerequisites checks + prepare
set -o errexit
set -o nounset
set -o pipefail
run "${version_sh}"

# Use unique image tag
version=$("${version_sh}" --version)
imagetag="${version}.${selfpid}"
imagename="${name}.${imagetag}"

# Create unique image
run mkdir -p "${workdir}"
cdx "${workdir}"

run env SILOFS_IMAGENAME="${imagename}" "${basedir}/dist/img/buildimg.sh"

# Execute unit-tests via image
scratchdir="${workdir}/scratch/"
run mkdir -p "${scratchdir}"
run rm -rf "${scratchdir}/*"

run podman run --rm \
  --userns keep-id:"uid=$(id -u),gid=$(id -g)" \
  --user="$(id -u):$(id -g)" \
  --volume="/etc/group:/etc/group:ro" \
  --volume="/etc/passwd:/etc/passwd:ro" \
  --volume="/etc/shadow:/etc/shadow:ro" \
  --volume="${scratchdir}:/scratch:rw" \
  --workdir="/scratch" \
  "${imagename}" "silofs-utests" "/scratch"

# Remove test image
run podman rmi "${imagename}"

# Post-op cleanups
cdx "${basedir}"
run rm -rf "${scratchdir}"

# Goodby ;)
msg "completed successfully"
exit 0
