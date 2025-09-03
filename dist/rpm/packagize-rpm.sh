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
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
rootdir=$(realpath "${selfdir}"/../../)
version_sh="${rootdir}"/version.sh
version=$(run "${version_sh}" --version)
release=$(run "${version_sh}" --release)
revision=$(run "${version_sh}" --revision)
archive_tgz=${name}-${version}.tar.gz

builddir=${rootdir}/build
rpmdistdir=${builddir}/dist
rpmhomedir=${rpmdistdir}/rpm
autotoolsdir=${rpmhomedir}/autotools/

rpmsourcedir=${selfdir}
rpmbuilddir=${RPMBUILDDIR:-${rpmhomedir}/rpmbuild}
rpmvardir=${rpmbuilddir}/var
rpmtmpdir=${rpmvardir}/tmp
rpmdate=$(date +"%a %b %d %Y")
rpmspec_in=${rpmsourcedir}/${name}.spec.in
rpmspec_out=${rpmbuilddir}/SPECS/${name}.spec

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
run command -v rpmbuild

# Bootstrap
cd "${rootdir}"
run "${rootdir}"/bootstrap

# Autotools build
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${rootdir}"/configure \
    "--enable-utests=1" "--enable-compile-warnings=error"
run make distcheck

# Pre rpmbuild
unset HOME
export HOME=${rpmhomedir}

# Prepare rpm tree
run mkdir -p "${rpmdistdir}"
run mkdir -p "${rpmtmpdir}"
run mkdir -p "${rpmbuilddir}"
run mkdir -p "${rpmbuilddir}"/BUILD
run mkdir -p "${rpmbuilddir}"/BUILDROOT
run mkdir -p "${rpmbuilddir}"/RPMS
run mkdir -p "${rpmbuilddir}"/SOURCES
run mkdir -p "${rpmbuilddir}"/SPECS
run mkdir -p "${rpmbuilddir}"/SRPMS

# Generate spec
run sed \
    -e "s,[@]PACKAGE_NAME[@],${name},g" \
    -e "s,[@]PACKAGE_VERSION[@],${version},g" \
    -e "s,[@]PACKAGE_RELEASE[@],${release},g" \
    -e "s,[@]PACKAGE_REVISION[@],${revision},g" \
    -e "s,[@]RPMDATE[@],${rpmdate},g" \
    "${rpmspec_in}" > "${rpmspec_out}"

# Copy dist archive
run cp "${autotoolsdir}/${archive_tgz}" "${rpmbuilddir}/SOURCES"

# Execute rpmbuild
cd "${rpmbuilddir}"
run env WITH_MYPY=0 rpmbuild -ba \
    --define "_topdir ${rpmbuilddir}" \
    --define "_var ${rpmvardir}" \
    "${rpmspec_out}"

# Copy rpms to dist-dir
cd "${rootdir}"
run mkdir -p "${rpmdistdir}"
run find \
    "${rpmbuilddir}"/RPMS/ \
    -type f -name ${name}'*.rpm' \
    -exec cp {} "${rpmdistdir}" \;

# Cleanup build staging area
# run rm -rf "${rpmhomedir}"

# Show result rpm files
run find "${rpmdistdir}" \
    -depth -maxdepth 1 \
    -type f -name ${name}'*.rpm' -exec basename {} \;

# Bye ;)
exit 0
