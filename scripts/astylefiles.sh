#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

command -v astyle > /dev/null
for src in "${@}"; do
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
    "${src}"
done
