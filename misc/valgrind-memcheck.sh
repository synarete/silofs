#!/bin/sh
exec valgrind -v --tool=memcheck --show-reachable=yes --leak-check=full "$@"


