# SPDX-License-Identifier: GPL-3.0
import string

from .ctx import TestEnv


def test_view_minimal(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs()
    env.exec_mount()
    path = env.make_path("abc")
    data = "\n".join([string.ascii_letters, string.digits])
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(data)
    path.unlink()
    env.exec_umount()
    view = env.exec_view()
    env.expect.gt(len(view), 1)
    env.exec_rmfs()


def test_view_data(env: TestEnv) -> None:
    env.exec_setup_fs(8)
    tds = env.make_tds(2, "C", 2**20)
    tds.do_makedirs()
    tds.do_write()
    env.exec_umount()
    view = env.exec_view()
    env.expect.gt(len(view), 10)
    env.exec_mount()
    tds.do_unlink()
    env.exec_umount()
    view = env.exec_view()
    env.expect.gt(len(view), 10)
    env.exec_rmfs()
