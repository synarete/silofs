# SPDX-License-Identifier: GPL-3.0
import copy

from .ctx import TestEnv


def test_fork_basic(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.create_data(128, "A", 2**20)
    env.exec_fork("fork1")
    tds.do_read()
    tds = env.create_data(128, "A", 2**20)
    env.exec_fork("fork2")
    tds.do_read()
    tds.do_unlink()
    env.exec_rmfs("fork1")
    env.exec_rmfs("fork2")
    env.exec_teardown_fs()


def test_fork_reload_twice(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(32, "main")
    env.exec_mount("main")
    tds1 = env.create_data(128, "A", 2**17)
    tds2 = env.create_data(128, "B", 2**20)
    env.exec_fork("fork1")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**21)
    tds2 = env.create_data(128, "B", 2**16)
    env.exec_fork("fork2")
    tds1.do_read()
    tds2.do_read()
    tds1.do_unlink()
    env.exec_umount()
    env.exec_rmfs("fork1")
    env.exec_mount("fork2")
    env.exec_rmfs("main")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**19)
    tds2 = env.create_data(128, "B", 2**19)
    tds1.do_unlink()
    tds2.do_unlink()
    env.exec_umount()
    env.exec_rmfs("fork2")


def test_fork_reload_multi(env: TestEnv) -> None:
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
        name, name_prev = f"fork{i}", name
        env.exec_fork(name)
        tds.do_read()
        tds_over = env.create_data(200, "A", 2**20)
        tds_over.do_read()
        env.exec_umount()
    env.exec_rmfs(name)


def test_fork_offline(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(10, "main")
    env.exec_mount("main")
    tds = env.create_data(10, "A", 2**20)
    env.exec_umount()
    env.exec_fork_offline("main", "fork1")
    env.exec_mount("fork1")
    tds.do_read()
    tds.do_unlink()
    tds = env.create_data(100, "B", 2**20)
    env.exec_umount()
    env.exec_fork_offline("fork1", "fork2")
    env.exec_rmfs("main")
    env.exec_rmfs("fork1")
    env.exec_mount("fork2")
    tds.do_read()
    env.exec_umount()
    env.exec_fork_offline("fork2", "fork3")
    env.exec_mount("fork3")
    tds.do_read()
    env.exec_rmfs("fork2")
    tds.do_read()
    tds.do_unlink()
    env.exec_umount()
    env.exec_rmfs("fork3")


def test_fork_repeated(env: TestEnv) -> None:
    forks = []
    fork_tds = []
    name = "main"
    env.exec_init()
    env.exec_mkfs(20, name)
    env.exec_mount(name)
    for i in range(1, 20):
        fork_name = f"fork{i}"
        tds = env.create_data(2, fork_name, 2**20)
        fork_tds.append(tds)
        env.exec_fork(fork_name)
        forks.append((fork_name, copy.copy(fork_tds)))
    env.exec_umount()
    for fork_name, fork_tds in forks:
        env.exec_mount(fork_name)
        for tds in fork_tds:
            tds.do_read()
            tds.do_unlink()
        env.exec_umount()
        env.exec_rmfs(fork_name)
