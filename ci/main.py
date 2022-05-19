# SPDX-License-Identifier: GPL-3.0
import sys
import os

from .tests import ctx
from .tests import run


def _progname() -> str:
    return os.path.basename(sys.argv[0])


def _die(msg: str) -> None:
    print("{}: {}".format(_progname(), msg))
    sys.exit(1)


def _usage(exit_code: int) -> None:
    print("usage: {} base-dir mount-point".format(_progname()))
    sys.exit(exit_code)


def _require_empty_dir(dirpath: str) -> None:
    if not os.path.isdir(dirpath):
        _die("not a directory: {}".format(dirpath))
    if os.listdir(dirpath):
        _die("not an empty directory: {}".format(dirpath))


def _makeconfig(basedir: str, mntdir: str) -> ctx.TestConfig:
    _require_empty_dir(basedir)
    _require_empty_dir(mntdir)
    return ctx.TestConfig(basedir, mntdir)


def _parseargs() -> tuple[str, str]:
    args = sys.argv
    if len(args[1:]) != 2:
        _usage(1)
    return (args[1], args[2])


def main() -> None:
    basedir, mntdir = _parseargs()
    cfg = _makeconfig(basedir, mntdir)
    run.run_tests(cfg)


if __name__ == "__main__":
    main()
