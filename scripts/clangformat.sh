#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
root=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
cd "${root}"
command -v clang-format > /dev/null
clang-format -i -style=file "$@"
