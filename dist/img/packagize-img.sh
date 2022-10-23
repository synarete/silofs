#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self:" "$@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH

name=silofs
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../../)
version_sh="${basedir}"/version.sh
version=$(try "${version_sh}" --version)
release=$(try "${version_sh}" --release)
revision=$(try "${version_sh}" --revision)
dist_name="${name}-${version}"
archive_tgz="${dist_name}.tar.gz"
arch=$(try uname -m)
tag_name="${name}-toolbox:v${version}"

imgsourcedir=${selfdir}
builddir=${basedir}/build
imgbuilddir=${builddir}/img
autotoolsdir=${imgbuilddir}/autotools/

# Prerequisites checks
run command -v aclocal
run command -v automake
run command -v libtoolize
run command -v rst2man
run command -v rst2html
run command -v basename
run command -v podman

# Autotools build
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${basedir}"/configure "--enable-unitests=1"
run make
run make distcheck

# Copy dist archive
run cp "${autotoolsdir}/${archive_tgz}" "${imgbuilddir}"

# Copy Containerfile
run cp "${imgsourcedir}/Containerfile" "${imgbuilddir}"

# Build target image with podman
run podman build \
  --build-arg=VERSION="${version}" \
  --build-arg=RELEASE="${release}" \
  --build-arg=REVISION="${revision}" \
  --build-arg=ARCH="${arch}" \
  --build-arg=DIST_NAME="${dist_name}" \
  --tag "${tag_name}" \
  --file "${imgbuilddir}/Containerfile" \
  "${imgbuilddir}"

# Cleanup build staging area
cd "${basedir}"
#run rm -rf "${imgbuilddir}"

# Bye ;)
exit 0



