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

name=silofs
arch=$(uname -m)
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../../)
version_sh="${basedir}"/version.sh
version=$(try "${version_sh}" --version)
release=$(try "${version_sh}" --release)
revision=$(try "${version_sh}" --revision)
dist_name="${name}-${version}"
archive_tgz="${dist_name}.tar.gz"
image_tag="v${version}"
image_name="${name}:${image_tag}"
imgsourcedir=${selfdir}
builddir=${basedir}/build
imgbuilddir=${builddir}/img
autotoolsdir=${imgbuilddir}/autotools/

# Prerequisites checks
try command -v aclocal > /dev/null
try command -v automake > /dev/null
try command -v libtoolize > /dev/null
try command -v rst2man > /dev/null
try command -v rst2html > /dev/null
try command -v basename > /dev/null
try command -v podman > /dev/null

# Autotools build
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${basedir}"/configure "--enable-unitests=0"
run make dist

# Copy dist archive
run cp "${autotoolsdir}/${archive_tgz}" "${imgbuilddir}"

# Copy Containerfile
run cp "${imgsourcedir}/Containerfile" "${imgbuilddir}"

# Build target images with podman
cd "${imgbuilddir}"
run podman build \
  --build-arg=VERSION="${version}" \
  --build-arg=RELEASE="${release}" \
  --build-arg=REVISION="${revision}" \
  --build-arg=DIST_NAME="${dist_name}" \
  --build-arg=ARCH="${arch}" \
  --tag "${image_name}" \
  --file "${imgbuilddir}/Containerfile" \
  "${imgbuilddir}"

# Cleanup build staging area
cd "${basedir}"
try rm -rf "${imgbuilddir}"


