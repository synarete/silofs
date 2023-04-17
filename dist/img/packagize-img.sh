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
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../../)
version_sh="${basedir}"/version.sh
version=$(try "${version_sh}" --version)
release=$(try "${version_sh}" --release)
revision=$(try "${version_sh}" --revision)
dist_name="${name}-${version}"
archive_tgz="${dist_name}.tar.gz"
image_tag="v${version}"
image_name="${name}-toolbox:${image_tag}"
registry="${SILOFS_REGISTRY:-}"

imgsourcedir=${selfdir}
builddir=${basedir}/build
imgbuilddir=${builddir}/img
autotoolsdir=${imgbuilddir}/autotools/
arch_list=(amd64 arm64)

# Prerequisites checks
run command -v aclocal
run command -v automake
run command -v libtoolize
run command -v rst2man
run command -v rst2html
run command -v basename
run command -v podman
run command -v buildah
run command -v skopeo
run command -v qemu-x86_64-static
run command -v qemu-aarch64-static


# Autotools build
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${basedir}"/configure "--enable-unitests=0"
run make dist

# Copy dist archive
run cp "${autotoolsdir}/${archive_tgz}" "${imgbuilddir}"

# Copy Containerfile
run cp "${imgsourcedir}/Containerfile" "${imgbuilddir}"

# Create manifest
run buildah manifest create "${image_name}"

# Build target images with buildah and add to manifest
cd "${imgbuilddir}"
for arch in "${arch_list[@]}"; do
  run buildah bud \
    --manifest "${image_name}" \
    --build-arg=VERSION="${version}" \
    --build-arg=RELEASE="${release}" \
    --build-arg=REVISION="${revision}" \
    --build-arg=DIST_NAME="${dist_name}" \
    --build-arg=ARCH="${arch}" \
    --arch "${arch}" \
    --tag "${image_name}-${arch}" \
    --file "${imgbuilddir}/Containerfile" \
    "${imgbuilddir}"
done

# Inspect manifest (post operation)
run buildah manifest inspect "${image_name}"

# Push multi-arch image to registry
if [ -n "$registry" ]; then
  run podman manifest push --all \
  	"${image_name}" "docker://${registry}/${image_name}"
fi

# Cleanup build staging area
cd "${basedir}"
run rm -rf "${imgbuilddir}"

# Bye ;)
exit 0



