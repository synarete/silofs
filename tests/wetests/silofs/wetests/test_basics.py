# SPDX-License-Identifier: GPL-3.0
import os
from . import ctx


def test_version(te: ctx.TestEnv) -> None:
    version = te.cmd.version()
    te.expect_gt(len(version), 0)


def test_init(te: ctx.TestEnv) -> None:
    te.do_init()


def test_mkfs(te: ctx.TestEnv) -> None:
    name = te.label
    te.do_init()
    te.do_mkfs(name)


def test_mount(te: ctx.TestEnv) -> None:
    name = te.label
    te.do_init()
    te.do_mkfs(name)
    te.do_mount(name)
    te.do_umount()


def test_simple_io(te: ctx.TestEnv) -> None:
    name = te.label
    te.do_init()
    te.do_mkfs(name)
    te.do_mount(name)
    name = os.path.join(te.cfg.mntdir, "hello")
    data = "hello, world!"
    with open(name, "w") as f:
        f.writelines(data)
    with open(name, "r") as f:
        lines = f.readlines()
    te.expect_eq(len(lines), 1)
    te.expect_eq(lines[0], data)
    te.do_umount()
