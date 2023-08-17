# SPDX-License-Identifier: GPL-3.0
import pathlib
import sys

from . import run


def _progname() -> str:
    return "silofs-citests"


def _usage(exit_code: int) -> None:
    print(f"usage: {_progname()} test-dir mount-point")
    sys.exit(exit_code)


def _parseargs() -> tuple[pathlib.Path, pathlib.Path]:
    args = sys.argv
    if len(args[1:]) != 2:
        _usage(1)
    test_dir = pathlib.Path(args[1])
    mnt_point = pathlib.Path(args[2])
    return (test_dir, mnt_point)


def start_citests() -> None:
    basedir, mntdir = _parseargs()
    cfg = run.make_config(basedir, mntdir)
    run.run_tests(cfg)
