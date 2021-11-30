#!/bin/sh
basedir=$(realpath $(dirname "$0")/../)
find "${basedir}" -type f -name '*.[ch]' -exec grep 'TODO-' {} \; | \
  sed 's/\t / /g' | \
  sort | \
  awk '{ sub(/^[ \t]+/, ""); print }'
