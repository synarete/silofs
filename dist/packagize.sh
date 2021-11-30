#!/bin/sh
set -e
base=$(dirname "$(realpath "$0")")
if [ -f '/etc/redhat-release' ]; then
  "${base}"/packagize-rpm.sh
elif [ -f '/etc/debian_version' ]; then
  "${base}"/packagize-deb.sh
else
  echo "unknown packaging system" && exit 1
fi
