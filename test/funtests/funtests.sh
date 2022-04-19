#!/bin/bash
# Developer's wrapper script
basedir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
PYTHONPATH=${basedir}:${PYTHONPATH} python3 -m silofs.funtestsmain "$@"
