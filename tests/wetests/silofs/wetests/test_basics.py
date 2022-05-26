# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_version(te: ctx.TestEnv) -> None:
    version = te.cmd.version()
    te.expect_len(version)


def test_init(te: ctx.TestEnv) -> None:
    te.do_init()


def test_mkfs(te: ctx.TestEnv) -> None:
    te.do_init()
    te.do_mkfs("test_mkfs")
