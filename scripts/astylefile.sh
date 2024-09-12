#!/usr/bin/env bash
self=$(basename "${BASH_SOURCE[0]}")
set -o errexit
set -o nounset
set -o pipefail

command -v astyle > /dev/null
for f in "${@}"; do
  astyle -Q \
    --style=1tbs \
    --suffix=none \
    --indent=tab=8 \
    --convert-tabs \
    --align-pointer=name \
    --pad-oper \
    --pad-header \
    --unpad-paren \
    --min-conditional-indent=0 \
    --indent-preprocessor \
    --add-braces \
    --add-one-line-braces \
    --break-after-logical \
    --max-code-length=79 \
    --indent-col1-comments \
    --lineend=linux \
    "${f}" | sed "s,^Formatted ,${self}:,g"
done
