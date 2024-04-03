# SPDX-License-Identifier: GPL-3.0
import sys
from pathlib import Path

from . import run


def _progname() -> str:
    return "silofs-qatests"


def _usage(exit_code: int) -> None:
    print(f"usage: {_progname()} test-dir mount-point")
    sys.exit(exit_code)


def _parseargs() -> tuple[Path, Path]:
    args = sys.argv
    if len(args[1:]) != 2:
        _usage(1)
    test_dir, mnt_point = Path(args[1]), Path(args[2])
    return (test_dir, mnt_point)


def start_qatests() -> None:
    basedir, mntdir = _parseargs()
    cfg = run.make_config(basedir, mntdir)
    run.run_tests(cfg)
