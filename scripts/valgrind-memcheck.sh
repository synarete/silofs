#!/bin/sh
valgrind -v --tool=memcheck --error-exitcode=1 \
  --show-reachable=yes --leak-check=full --track-origins=yes "$@"


