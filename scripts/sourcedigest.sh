#!/usr/bin/env bash
# Calculate unique sha256 hash-value of project's files
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
selfdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

cd "${selfdir}/../"
find . -type f -name '*.[ch]' -print \
    | sort -u \
    | xargs sha256sum \
    | sha256sum \
    | awk '{print $1}'
