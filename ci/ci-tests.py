#!/usr/bin/env python3
import sys
import os

cdir = os.path.dirname(__file__)
xdir = os.path.realpath(os.path.join(cdir, ".."))
if xdir not in sys.path:
    sys.path = [xdir] + sys.path

# pylint: disable=C0413
if __name__ == "__main__":
    import ci.main as cimain

    cimain.main()
