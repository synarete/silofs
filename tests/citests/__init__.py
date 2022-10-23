# SPDX-License-Identifier: GPL-3.0
import sys

from . import ctx
from . import run


def _progname() -> str:
    return "silofs-citests"


def _usage(exit_code: int) -> None:
    print(f"usage: {_progname()} test-dir mount-point")
    sys.exit(exit_code)


def _makeconfig(basedir: str, mntdir: str) -> ctx.TestConfig:
    return ctx.TestConfig(basedir, mntdir)


def _parseargs() -> tuple[str, str]:
    args = sys.argv
    if len(args[1:]) != 2:
        _usage(1)
    return (args[1], args[2])


def citests_main() -> None:
    basedir, mntdir = _parseargs()
    cfg = _makeconfig(basedir, mntdir)
    run.run_tests(cfg)


if __name__ == "__main__":
    citests_main()
