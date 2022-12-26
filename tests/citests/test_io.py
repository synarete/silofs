# SPDX-License-Identifier: GPL-3.0
import os
from . import ctx


def test_rw_text(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    path = tc.make_path("text")
    data = ["abcdefghijklmnopqrstuvwxyz\n", "0123456789\n"]
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(data)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    tc.expect.eq(len(lines), len(data))
    tc.expect.eq(lines, data)
    os.unlink(path)
    tc.exec_umount()


def test_rw_rands(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    tds = tc.make_tds(1, "A", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds = tc.make_tds(1024, "B", 4096)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tc.exec_umount()


def test_reload(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs(8)
    tds = tc.make_tds(2, "C", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tc.exec_umount()
    tc.exec_mount()
    tds.do_read()
    tds.do_unlink()
    tds = tc.make_tds(1024, "D", 4096)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tc.exec_umount()
    tc.exec_mount()
    tds.do_read()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tc.exec_umount()


def test_reload_n(tc: ctx.TestCtx) -> None:
    tds_all: list[ctx.TestDataSet] = []
    tc.exec_setup_fs(64)
    tc.exec_umount()
    for i in range(0, 20):
        tc.exec_mount()
        for tds in tds_all:
            tds.do_read()
        tds = tc.make_tds(i + 1, f"x{i}", 2**20 + i)
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        tds_all.append(tds)
        tc.exec_umount()
    tc.exec_mount()
    for tds in tds_all:
        tds.do_read()
        tds.do_unlink()
    tc.exec_umount()


def test_rw_kcopy(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs(32)
    tc.exec_mount(kcopy=True)
    tds = tc.make_tds(16, "E", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds = tc.make_tds(1024, "F", 4096)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tc.exec_umount()
