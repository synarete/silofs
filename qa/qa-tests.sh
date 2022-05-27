#!/bin/bash
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../)
cd ${basedir} || exit 1
PYTHONPATH=${basedir}:${PYTHONPATH} python3 -m qa.main "$@"
