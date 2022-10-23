# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_fsck_basic(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    tds = tc.make_tds(100, "A", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_stat()
    tds.do_read()
    tc.exec_umount()
    tc.exec_fsck()


def test_fsck_snap(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    tds = tc.make_tds(100, "B", 2**21)
    tds.do_makedirs()
    tds.do_write()
    tds.do_stat()
    tds.do_read()
    tc.exec_snap("snap1")
    tds.do_read()
    tds = tc.make_tds(50, "C", 2**22)
    tds.do_makedirs()
    tds.do_write()
    tc.exec_snap("snap2")
    tds.do_read()
    tc.exec_umount()
    tc.exec_fsck("snap1")
    tc.exec_fsck("snap2")
