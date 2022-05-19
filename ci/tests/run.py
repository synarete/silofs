# SPDX-License-Identifier: GPL-3.0

from . import ctx
from . import test_basics
from . import fsutils

TESTS = [
    test_basics.test_version,
    test_basics.test_init,
    test_basics.test_mkfs,
    test_basics.test_mount,
    test_basics.test_simple_io,
]


def _list_tests() -> list[ctx.TestDef]:
    return [ctx.TestDef(test) for test in TESTS]


def _pre_run_tests() -> None:
    pass


def _pre_test(te: ctx.TestEnv) -> None:
    te.expect_empty_dir(te.cfg.basedir)
    te.expect_empty_dir(te.cfg.mntdir)


def _post_test(te: ctx.TestEnv) -> None:
    fsutils.empty_dir(te.cfg.mntdir)
    fsutils.empty_dir(te.cfg.basedir)


def _exec_test(te: ctx.TestEnv, td: ctx.TestDef) -> None:
    print("RUN: {}".format(td.name))
    te.set_label(td.name)
    td.hook(te)
    te.set_label("")


def run_tests(cfg: ctx.TestConfig) -> None:
    _pre_run_tests()
    te = ctx.TestEnv(cfg)
    for test in _list_tests():
        _pre_test(te)
        _exec_test(te, test)
        _post_test(te)
