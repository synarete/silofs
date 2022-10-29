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
archive_tgz=${name}-${version}.tar.gz

builddir=${basedir}/build
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

# Prerequisites checks
run command -v aclocal
run command -v automake
run command -v libtoolize
run command -v rst2man
run command -v rst2html
run command -v basename
run command -v rpmbuild

# Bootstrap
cd "${basedir}"
run "${basedir}"/bootstrap

# Autotools build
run mkdir -p "${autotoolsdir}"
cd "${autotoolsdir}"
run "${basedir}"/configure "--enable-unitests=1"
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
  -e "s,[@]NAME[@],${name},g" \
  -e "s,[@]VERSION[@],${version},g" \
  -e "s,[@]RELEASE[@],${release},g" \
  -e "s,[@]REVISION[@],${revision},g" \
  -e "s,[@]RPMDATE[@],${rpmdate},g" \
  "${rpmspec_in}" > "${rpmspec_out}"

# Copy dist archive
run cp "${autotoolsdir}/${archive_tgz}" "${rpmbuilddir}/SOURCES"

# Execute rpmbuild
cd "${rpmbuilddir}"
run rpmbuild -ba \
  --define "_topdir ${rpmbuilddir}" \
  --define "_var ${rpmvardir}" \
  "${rpmspec_out}"

# Copy rpms to dist-dir
cd "${basedir}"
run mkdir -p "${rpmdistdir}"
run find \
  "${rpmbuilddir}"/RPMS/ \
  -type f -name ${name}'*.rpm' \
  -exec cp {} "${rpmdistdir}" \;

# Cleanup build staging area
# run rm -rf "${rpmhomedir}"

# Show result rpm files
run find "${rpmdistdir}" -type f -name ${name}'*.rpm' -exec basename {} \;

# Bye ;)
exit 0



