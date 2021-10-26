#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
root=$(readlink -f "$(dirname "${self}")")
checkcstyle_py="${root}"/misc/checkcstyle.py

srcs=$(find "${root}/include" "${root}/src" "${root}/test" \
        -type f -not -name "fuse7.h" -not -name "configs.h" \
        -name "*.[ch]")
${checkcstyle_py} ${srcs}
