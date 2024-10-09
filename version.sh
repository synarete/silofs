#!/usr/bin/env bash
IFS=$'\n\t'
self=$(readlink -f "$0")
base=$(dirname "${self}")
datenow=$(date +%Y%m%d)

# Detect if within git repo
cd "${base}" || exit 1
export GIT_DIR="${base}/.git"
gittop=$(git rev-parse --show-toplevel > /dev/null 2>&1 && echo -n "git-repo")

if [ -n "${gittop}" ]; then
  gitrevision=$(git describe --abbrev=8 --always --dirty=+)
  # gitrevision=$(git rev-parse --short=7 HEAD)
else
  gitrevision=""
fi

# Detect version string sub-components
set -o errexit
set -o nounset
set -o pipefail

print() {
  echo -n "$@" | tr -d ' \t\v\n' ;
}

version=${SILOFS_VERSION:-1}
if [ -e "${base}/VERSION" ]; then
  version=$(head -1 "${base}"/VERSION)
fi
version_major=$(echo "${version}" | awk -F . '{print $1}')
version_minor=$(echo "${version}" | awk -F . '{print $2}')
version_sublevel=$(echo "${version}" | awk -F . '{print $3}')

release=${SILOFS_RELEASE:-${datenow}}
if [ -e "${base}/RELEASE" ]; then
  release=$(head -1 "${base}/RELEASE")
fi

revision=${SILOFS_REVISION:-1}
if [ -e "${base}/REVISION" ]; then
  revision=$(head -1 "${base}"/REVISION)
fi
if [ -n "${gitrevision}" ]; then
  revision=${gitrevision}
fi


arg=${1:-}
case "$arg" in
  -h|--help)
    echo "${self}" "[--version|--major|--minor|--sublevel|--release|--revision]"
    ;;
  -v|--version)
    print "${version}"
    ;;
  -m|--major)
    print "${version_major}"
    ;;
  -n|--minor)
    print "${version_minor}"
    ;;
  -k|--sublevel)
    print "${version_sublevel}"
    ;;
  -r|--release)
    print "${release}"
    ;;
  -g|--revision)
    print "${revision}"
    ;;
  *)
    print "${version}-${release}.${revision}"
    echo
    ;;
esac
