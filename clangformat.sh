#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
root=$(readlink -f "$(dirname "${self}")")
srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/cmd" "${root}/mntd" "${root}/tests" \
  -type f -not -name "fuse7.h" -not -name "configs.h" -name "*.[ch]")

cd "${root}"
command -v clang-format > /dev/null
clang-format -i -style=file ${srcs}
