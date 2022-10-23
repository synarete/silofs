#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
root=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")

gitlint --target="${root}" --config="${root}/scripts/gitlint.conf"
