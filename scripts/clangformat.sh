#!/bin/bash -e
root=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/tools" "${root}/tests" \
  -type f -not -name "fuse7.h" -not -name "configs.h" -name "*.[ch]")

cd "${root}"
command -v clang-format > /dev/null
clang-format -i -style=file ${srcs}
