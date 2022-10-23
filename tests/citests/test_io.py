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
