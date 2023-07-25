# SPDX-License-Identifier: GPL-3.0
import pathlib
import sys

from . import ctx
from . import run

setproctitle = None
try:
    from setproctitle import setproctitle  # type: ignore
except ImportError:
    pass


def _progname() -> str:
    return "silofs-citests"


def _usage(exit_code: int) -> None:
    print(f"usage: {_progname()} test-dir mount-point")
    sys.exit(exit_code)


def _makeconfig(basedir: pathlib.Path, mntdir: pathlib.Path) -> ctx.TestConfig:
    return ctx.TestConfig(basedir, mntdir)


def _parseargs() -> tuple[pathlib.Path, pathlib.Path]:
    args = sys.argv
    if len(args[1:]) != 2:
        _usage(1)
    test_dir = pathlib.Path(args[1])
    mnt_point = pathlib.Path(args[2])
    return (test_dir, mnt_point)


def _setproctitle() -> None:
    if setproctitle is not None:
        setproctitle("silofs-citests")


def citests_main() -> None:
    _setproctitle()
    basedir, mntdir = _parseargs()
    cfg = _makeconfig(basedir, mntdir)
    run.run_tests(cfg)


if __name__ == "__main__":
    citests_main()
