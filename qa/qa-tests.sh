#!/bin/bash
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
PYTHONPATH=${selfdir}:${PYTHONPATH} python3 -m main "$@"
