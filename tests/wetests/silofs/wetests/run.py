# SPDX-License-Identifier: GPL-3.0

from . import ctx
from . import test_basics

TESTS = [
    test_basics.test_version,
    test_basics.test_init,
    test_basics.test_mkfs,
]


def _list_tests() -> list[ctx.TestDef]:
    return [ctx.TestDef(test) for test in TESTS]


def _pre_test(te: ctx.TestEnv) -> None:
    te.expect_emptydir(te.cfg.basedir)
    te.expect_emptydir(te.cfg.mntdir)


def _post_test(te: ctx.TestEnv) -> None:
    te.emptydir(te.cfg.mntdir)
    te.emptydir(te.cfg.basedir)


def _exec_test(te: ctx.TestEnv, td: ctx.TestDef) -> None:
    print("test: {}".format(td.name))
    td.hook(te)


def run_tests(cfg: ctx.TestConfig) -> None:
    te = ctx.TestEnv(cfg)
    for test in _list_tests():
        _pre_test(te)
        _exec_test(te, test)
        _post_test(te)
