#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH
set -o errexit
set -o nounset
set -o pipefail

self="$(basename "${BASH_SOURCE[0]}")"
selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../../)"
source "${rootdir}/bash_functions"

name=silofs
version_sh=${rootdir}/version.sh
version=$(run "${version_sh}" --version)
release=$(run "${version_sh}" --release)
revision=$(run "${version_sh}" --revision)
archive_tgz=${name}-${version}.tar.gz

builddir=${rootdir}/build
buildauxdir=${builddir}/deb
debdistdir=${builddir}/pkg
autotoolsdir=${buildauxdir}/autotools/

debsourcedir=${selfdir}
debbuilddir=${buildauxdir}/debbuild
deborig_archive=${name}_${version}.orig.tar.gz
debrelease_archive=${name}_${version}-${release}.debian.tar.gz
debbuild_distdir=${debbuilddir}/${name}-${version}
debbuild_debiandir=${debbuild_distdir}/debian

# System info
run uname --all
run gcc --version | head -1

# Prerequisites checks
run command -v aclocal
run command -v automake
run command -v libtoolize
run command -v rst2man
run command -v rst2html
run command -v basename
run command -v dpkg-buildpackage
run command -v dh

# Bootstrap
cd "${rootdir}"
run "${rootdir}"/bootstrap

# Autotools build
py3sitedir=$(python3 -c "import site; print(site.getsitepackages()[-1])")
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${rootdir}"/configure \
    "--enable-utests=0" \
    "--enable-compile-warnings=error" \
    "--with-python-site-packages=${py3sitedir}"
run make
run make distcheck

# Prepare deb tree
run mkdir -p "${debbuilddir}"
run mkdir -p "${debbuild_distdir}"
run mkdir -p "${debbuild_debiandir}"

# Copy and extract dist archives
run cp "${autotoolsdir}/${archive_tgz}" "${debbuilddir}/"
run cp "${autotoolsdir}/${archive_tgz}" "${debbuilddir}/${deborig_archive}"
run cp "${autotoolsdir}/${archive_tgz}" "${debbuilddir}/${debrelease_archive}"
cd "${debbuilddir}"
run tar xvfz "${archive_tgz}"

# Prepare deb files
cd "${rootdir}"
run mkdir -p "${debbuild_debiandir}"/source
run cp "${debsourcedir}"/format "${debbuild_debiandir}"/source
run cp "${debsourcedir}"/control "${debbuild_debiandir}"
run cp "${debsourcedir}"/copyright "${debbuild_debiandir}"
run cp "${debsourcedir}"/docs "${debbuild_debiandir}"
run cp "${debsourcedir}"/README.Debian "${debbuild_debiandir}"
run cp "${debsourcedir}"/rules "${debbuild_debiandir}"
run cp "${debsourcedir}"/silofs.install "${debbuild_debiandir}"
run cp "${debsourcedir}"/not-installed "${debbuild_debiandir}"
run sed -e "s|usr/lib/python3/dist-packages|${py3sitedir#/}|" \
    "${debsourcedir}"/silofs-tests.install \
    > "${debbuild_debiandir}"/silofs-tests.install
run cp "${debsourcedir}"/silofs.postinst "${debbuild_debiandir}"
run cp "${debsourcedir}"/silofs.prerm "${debbuild_debiandir}"
run cp "${debsourcedir}"/silofs.postrm "${debbuild_debiandir}"


# Generate changelog
run sed \
    -e "s,[@]PACKAGE_NAME[@],${name},g" \
    -e "s,[@]PACKAGE_VERSION[@],${version},g" \
    -e "s,[@]PACKAGE_RELEASE[@],${release},g" \
    -e "s,[@]PACKAGE_REVISION[@],${revision},g" \
    "${debsourcedir}"/changelog.in > "${debbuild_debiandir}"/changelog

# Build deb package
cd "${debbuild_distdir}"
run env WITH_MYPY=0 dpkg-buildpackage -us -uc

# Copy debs to root of build-dir
run mkdir -p "${debdistdir}"
run find "${debbuilddir}/" \
    -type f -name "${name}_${version}"'*.deb' \
    -exec cp {} "${debdistdir}" \;

# Cleanup build staging area
cd "${rootdir}"
run rm -rf "${buildauxdir}"

# Show result deb files
run find "${debdistdir}" -type f -name ${name}'*.deb' -exec basename {} \;

# Bye ;)
exit 0
