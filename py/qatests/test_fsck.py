# SPDX-License-Identifier: GPL-3.0
from .ctx import TestEnv


def test_fsck_basic(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.make_tds(100, "A", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_stat()
    tds.do_read()
    env.exec_umount()
    env.exec_fsck()


def test_fsck_clone(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.make_tds(100, "B", 2**21)
    tds.do_makedirs()
    tds.do_write()
    tds.do_stat()
    tds.do_read()
    env.exec_clone("clone1")
    tds.do_read()
    tds = env.make_tds(50, "C", 2**22)
    tds.do_makedirs()
    tds.do_write()
    env.exec_clone("clone2")
    tds.do_read()
    env.exec_umount()
    env.exec_fsck("clone1")
    env.exec_fsck("clone2")
