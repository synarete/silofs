# SPDX-License-Identifier: GPL-3.0
import copy

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


def test_snap_reload_twice(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs(32, "main")
    tc.exec_mount("main")
    tds1 = tc.create_data(128, "A", 2**17)
    tds2 = tc.create_data(128, "B", 2**20)
    tc.exec_snap("snap1")
    tds1.do_read()
    tds2.do_read()
    tds1 = tc.create_data(128, "A", 2**21)
    tds2 = tc.create_data(128, "B", 2**16)
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
    tds1 = tc.create_data(128, "A", 2**19)
    tds2 = tc.create_data(128, "B", 2**19)
    tds1.do_unlink()
    tds2.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs("snap2")


def test_snap_reload_multi(tc: ctx.TestCtx) -> None:
    name = "main"
    name_prev = ""
    tc.exec_init()
    tc.exec_mkfs(20, name)
    tc.exec_mount(name)
    tds = tc.create_data(200, "A", 2**20)
    tc.exec_umount()
    for i in range(1, 20):
        tc.exec_mount(name)
        if name_prev:
            tc.exec_rmfs(name_prev)
        tds.do_read()
        tds = tc.create_data(200, "A", 2**20)
        name, name_prev = f"snap{i}", name
        tc.exec_snap(name)
        tds.do_read()
        tds_over = tc.create_data(200, "A", 2**20)
        tds_over.do_read()
        tc.exec_umount()
    tc.exec_rmfs(name)


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


def test_snap_repeated(tc: ctx.TestCtx) -> None:
    snaps = []
    snap_tds = []
    name = "main"
    tc.exec_init()
    tc.exec_mkfs(20, name)
    tc.exec_mount(name)
    for i in range(1, 20):
        snap_name = f"snap{i}"
        tds = tc.create_data(2, snap_name, 2**20)
        snap_tds.append(tds)
        tc.exec_snap(snap_name)
        snaps.append((snap_name, copy.copy(snap_tds)))
    tc.exec_umount()
    for snap_name, snap_tds in snaps:
        tc.exec_mount(snap_name)
        for tds in snap_tds:
            tds.do_read()
            tds.do_unlink()
        tc.exec_umount()
        tc.exec_rmfs(snap_name)
