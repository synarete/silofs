# SPDX-License-Identifier: GPL-3.0
import copy

from .ctx import TestDef, TestEnv


def _test_clone_basic(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.create_data(128, "A", 2**20)
    env.exec_clone("clone1")
    tds.do_read()
    tds = env.create_data(128, "A", 2**20)
    env.exec_clone("clone2")
    tds.do_read()
    tds.do_unlink()
    env.exec_rmfs("clone1")
    env.exec_rmfs("clone2")
    env.exec_teardown_fs()


def _test_clone_reload_twice(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(32, "main")
    env.exec_mount("main")
    tds1 = env.create_data(128, "A", 2**17)
    tds2 = env.create_data(128, "B", 2**20)
    env.exec_clone("clone1")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**21)
    tds2 = env.create_data(128, "B", 2**16)
    env.exec_clone("clone2")
    tds1.do_read()
    tds2.do_read()
    tds1.do_unlink()
    env.exec_umount()
    env.exec_rmfs("clone1")
    env.exec_mount("clone2")
    env.exec_rmfs("main")
    tds1.do_read()
    tds2.do_read()
    tds1 = env.create_data(128, "A", 2**19)
    tds2 = env.create_data(128, "B", 2**19)
    tds1.do_unlink()
    tds2.do_unlink()
    env.exec_umount()
    env.exec_rmfs("clone2")


def _test_clone_reload_multi(env: TestEnv) -> None:
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
        name, name_prev = f"clone{i}", name
        env.exec_clone(name)
        tds.do_read()
        tds_over = env.create_data(200, "A", 2**20)
        tds_over.do_read()
        env.exec_umount()
    env.exec_rmfs(name)


def _test_clone_offline(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs(10, "main")
    env.exec_mount("main")
    tds = env.create_data(10, "A", 2**20)
    env.exec_umount()
    env.exec_clone_offline("main", "clone1")
    env.exec_mount("clone1")
    tds.do_read()
    tds.do_unlink()
    tds = env.create_data(100, "B", 2**20)
    env.exec_umount()
    env.exec_clone_offline("clone1", "clone2")
    env.exec_rmfs("main")
    env.exec_rmfs("clone1")
    env.exec_mount("clone2")
    tds.do_read()
    env.exec_umount()
    env.exec_clone_offline("clone2", "clone3")
    env.exec_mount("clone3")
    tds.do_read()
    env.exec_rmfs("clone2")
    tds.do_read()
    tds.do_unlink()
    env.exec_umount()
    env.exec_rmfs("clone3")


def _test_clone_repeated(env: TestEnv) -> None:
    clones = []
    clone_tds = []
    name = "main"
    env.exec_init()
    env.exec_mkfs(20, name)
    env.exec_mount(name)
    for i in range(1, 20):
        clone_name = f"clone{i}"
        tds = env.create_data(2, clone_name, 2**20)
        clone_tds.append(tds)
        env.exec_clone(clone_name)
        clones.append((clone_name, copy.copy(clone_tds)))
    env.exec_umount()
    for clone_name, clone_tds in clones:
        env.exec_mount(clone_name)
        for tds in clone_tds:
            tds.do_read()
            tds.do_unlink()
        env.exec_umount()
        env.exec_rmfs(clone_name)


def list_tests() -> list[TestDef]:
    return [
        TestDef(_test_clone_basic),
        TestDef(_test_clone_reload_twice),
        TestDef(_test_clone_reload_multi),
        TestDef(_test_clone_offline),
        TestDef(_test_clone_repeated),
    ]
