# SPDX-License-Identifier: GPL-3.0
from .ctx import TestDataSet, TestEnv


def test_rw_text(env: TestEnv) -> None:
    env.exec_setup_fs()
    path = env.make_path("text")
    data = ["abcdefghijklmnopqrstuvwxyz\n", "0123456789\n"]
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(data)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    env.expect.eq(len(lines), len(data))
    env.expect.eq(lines, data)
    path.unlink()
    env.exec_teardown_fs()


def test_rw_rands(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.make_tds(1, "A", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    tds = env.make_tds(1024, "B", 4096)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    tds = env.make_tds(64, "C", 2**20)
    subs = tds.do_makedirs()
    env.exec_tune2(subs)
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    env.exec_teardown_fs()


def test_reload(env: TestEnv) -> None:
    env.exec_setup_fs(8)
    tds = env.make_tds(2, "C", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    env.exec_umount()
    env.exec_mount()
    env.exec_lsmnt()
    tds.do_read()
    tds.do_unlink()
    tds = env.make_tds(1024, "D", 4096)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    env.exec_umount()
    env.exec_mount()
    env.exec_lsmnt()
    tds.do_read()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    env.exec_teardown_fs()


def test_reload_n(env: TestEnv) -> None:
    tds_all: list[TestDataSet] = []
    env.exec_setup_fs(64)
    env.exec_umount()
    for i in range(0, 20):
        env.exec_mount()
        for tds in tds_all:
            tds.do_read()
        tds = env.make_tds(i + 1, f"x{i}", 2**20 + i)
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        tds_all.append(tds)
        env.exec_umount()
    env.exec_mount()
    for tds in tds_all:
        tds.do_read()
        tds.do_unlink()
    env.exec_teardown_fs()


def run_async_io(tds: TestDataSet, cnt: int) -> None:
    while cnt > 0:
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        tds.do_unlink()
        tds.do_rmdirs()
        cnt = cnt - 1


def test_async_io(env: TestEnv) -> None:
    env.exec_setup_fs(64)
    fus = []
    for i in range(0, 64):
        sub = f"async-io{i}"
        tds = env.make_tds(16, sub, i + 2**20)
        fui = env.executor.submit(run_async_io, tds, i + 1)
        fus.append(fui)
    for fui in fus:
        fui.result()
    env.exec_teardown_fs()
