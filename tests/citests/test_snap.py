# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_snap_basic(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    tds = tc.create_data(128, "A", 2**20)
    tc.exec_snap("snap1")
    tds.do_read()
    tds = tc.create_data(128, "A", 2**20)
    tc.exec_snap("snap2")
    tds.do_read()
    tds.do_unlink()
    tc.exec_rmfs("snap1")
    tc.exec_rmfs("snap2")
    tc.exec_umount()


def test_snap_reload(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs(32, "main")
    tc.exec_mount("main")
    tds1 = tc.create_data(128, "A", 2**17, "x")
    tds2 = tc.create_data(128, "B", 2**20)
    tc.exec_snap("snap1")
    tds1.do_read()
    tds2.do_read()
    tds1 = tc.create_data(128, "A", 2**17, "y")
    tds2 = tc.create_data(128, "B", 2**20)
    tc.exec_snap("snap2")
    tds1.do_read()
    tds2.do_read()
    tds1.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs("snap1")
    tc.exec_mount("snap2")
    tc.exec_rmfs("main")
    tds1.do_read()
    tds2.do_read()
    tds1 = tc.create_data(128, "A", 2**17, "z")
    tds2 = tc.create_data(128, "B", 2**20)
    tds1.do_unlink()
    tds2.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs("snap2")


def test_snap_offline(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs(10, "main")
    tc.exec_mount("main")
    tds = tc.create_data(10, "A", 2**20)
    tc.exec_umount()
    tc.exec_snap_offline("main", "snap1")
    tc.exec_mount("snap1")
    tds.do_read()
    tds.do_unlink()
    tds = tc.create_data(100, "B", 2**20)
    tc.exec_umount()
    tc.exec_snap_offline("snap1", "snap2")
    tc.exec_rmfs("main")
    tc.exec_rmfs("snap1")
    tc.exec_mount("snap2")
    tds.do_read()
    tc.exec_umount()
    tc.exec_snap_offline("snap2", "snap3")
    tc.exec_mount("snap3")
    tds.do_read()
    tc.exec_rmfs("snap2")
    tds.do_read()
    tds.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs("snap3")
