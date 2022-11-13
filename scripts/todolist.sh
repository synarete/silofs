#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
basedir=$(realpath "$(dirname "$0")"/../)
find "${basedir}" -type f -name '*.[ch]' -exec grep 'TODO-' {} \; | \
  sed -e 's/\t / /g' -e 's/\/\*/ /g' -e 's/\*\// /g' -e 's/\* / /g'| \
  sort | \
  awk '{ sub(/^[ \t]+/, ""); print }'
