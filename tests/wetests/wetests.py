#!/usr/bin/env python3
import sys
import os

def main():
    xdir = os.path.dirname(os.path.realpath(__file__))
    if xdir not in sys.path:
        sys.path = [ xdir ] + sys.path

    from silofs import wetestsmain
    wetestsmain.main()

if __name__ == "__main__":
    main()
