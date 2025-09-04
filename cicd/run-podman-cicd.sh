#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH

# Do nothing if podman is missing
command -v podman > /dev/null || exit 0

# Common variables
name=silofs
selfpid="$$"
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
workdir="${rootdir}/build/cicd"
autotoolsdir="${workdir}/autotools/"
version_sh="${rootdir}"/version.sh

# Prerequisites checks + prepare
set -o errexit
set -o nounset
set -o pipefail
source "${rootdir}/bash_functions"
run "${version_sh}"

# Use unique image tag
version=$("${version_sh}" --version)
imagetag="${version}.${selfpid}"
imagename="${name}.${imagetag}"

# Create unique image
run mkdir -p "${workdir}"
cdx "${workdir}"

run env SILOFS_IMAGENAME="${imagename}" "${rootdir}/dist/img/buildimg.sh"

# Execute unit-tests via image
scratchdir="${workdir}/scratch/"
run mkdir -p "${scratchdir}"
run rm -rf "${scratchdir}/*"

run podman run --tty --rm \
    --userns keep-id:"uid=$(id -u),gid=$(id -g)" \
    --user="$(id -u):$(id -g)" \
    --volume="/etc/group:/etc/group:ro" \
    --volume="/etc/passwd:/etc/passwd:ro" \
    --volume="/etc/shadow:/etc/shadow:ro" \
    --volume="${scratchdir}:/scratch:rw" \
    --workdir="/scratch" \
    "${imagename}" "silofs-utests" "--level=1" "/scratch"

# Remove test image
run podman rmi "${imagename}"
run podman image prune -f

# Post-op cleanups
cdx "${rootdir}"
run rm -rf "${scratchdir}"

# Goodby ;)
msg "completed successfully"
exit 0
