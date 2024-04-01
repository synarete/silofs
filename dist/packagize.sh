#!/bin/sh
self="$0"
selfdir=$(realpath "$(dirname "${self}")")

if [ -f "/etc/redhat-release" ]; then
  exec sh -c "${selfdir}/rpm/packagize-rpm.sh"
elif [ -f "/etc/debian_version" ]; then
  exec sh -c "${selfdir}/deb/packagize-deb.sh"
else
  echo "${self}: unsupported dist"
  exit 1
fi

