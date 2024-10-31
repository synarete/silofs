# SPDX-License-Identifier: GPL-3.0
import copy

from .ctx import TestEnv


def test_snap_basic(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.create_data(128, "A", 2**20)
    env.exec_snap("snap1")
    tds.do_read()
    tds = env.create_data(128, "A", 2**20)
    env.exec_snap("snap2")
    tds.do_read()
    tds.do_unlink()
    env.exec_rmfs("snap1")
    env.exec_rmfs("snap2")
    env.exec_teardown_fs()


def test_snap_reload_twice(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(32, "main")
    env.exec_mount("main")
    tds1 = env.create_data(128, "A", 2**17)
    tds2 = env.create_data(128, "B", 2**20)
    env.exec_snap("snap1")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**21)
    tds2 = env.create_data(128, "B", 2**16)
    env.exec_snap("snap2")
    tds1.do_read()
    tds2.do_read()
    tds1.do_unlink()
    env.exec_umount()
    env.exec_rmfs("snap1")
    env.exec_mount("snap2")
    env.exec_rmfs("main")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**19)
    tds2 = env.create_data(128, "B", 2**19)
    tds1.do_unlink()
    tds2.do_unlink()
    env.exec_umount()
    env.exec_rmfs("snap2")


def test_snap_reload_multi(env: TestEnv) -> None:
    name = "main"
    name_prev = ""
    env.exec_init()
    env.exec_mkfs(20, name)
    env.exec_mount(name)
    tds = env.create_data(200, "A", 2**20)
    env.exec_umount()
    for i in range(1, 20):
        env.exec_mount(name)
        if name_prev:
            env.exec_rmfs(name_prev)
        tds.do_read()
        tds = env.create_data(200, "A", 2**20)
        name, name_prev = f"snap{i}", name
        env.exec_snap(name)
        tds.do_read()
        tds_over = env.create_data(200, "A", 2**20)
        tds_over.do_read()
        env.exec_umount()
    env.exec_rmfs(name)


def test_snap_offline(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(10, "main")
    env.exec_mount("main")
    tds = env.create_data(10, "A", 2**20)
    env.exec_umount()
    env.exec_snap_offline("main", "snap1")
    env.exec_mount("snap1")
    tds.do_read()
    tds.do_unlink()
    tds = env.create_data(100, "B", 2**20)
    env.exec_umount()
    env.exec_snap_offline("snap1", "snap2")
    env.exec_rmfs("main")
    env.exec_rmfs("snap1")
    env.exec_mount("snap2")
    tds.do_read()
    env.exec_umount()
    env.exec_snap_offline("snap2", "snap3")
    env.exec_mount("snap3")
    tds.do_read()
    env.exec_rmfs("snap2")
    tds.do_read()
    tds.do_unlink()
    env.exec_umount()
    env.exec_rmfs("snap3")


def test_snap_repeated(env: TestEnv) -> None:
    snaps = []
    snap_tds = []
    name = "main"
    env.exec_init()
    env.exec_mkfs(20, name)
    env.exec_mount(name)
    for i in range(1, 20):
        snap_name = f"snap{i}"
        tds = env.create_data(2, snap_name, 2**20)
        snap_tds.append(tds)
        env.exec_snap(snap_name)
        snaps.append((snap_name, copy.copy(snap_tds)))
    env.exec_umount()
    for snap_name, snap_tds in snaps:
        env.exec_mount(snap_name)
        for tds in snap_tds:
            tds.do_read()
            tds.do_unlink()
        env.exec_umount()
        env.exec_rmfs(snap_name)
