# SPDX-License-Identifier: GPL-3.0

from .ctx import TestEnv


def test_archive_basic(env: TestEnv) -> None:
    env.exec_setup_fs()
    tds = env.create_data(10, "A", 2**20)
    tds.do_read()
    env.exec_umount()
    arname = "ar1"
    env.exec_archive(arname)
    env.exec_rmfs()
    env.exec_restore(arname)
    env.exec_mount()
    tds.do_read()
    tds.do_unlink()
    env.exec_umount()
    env.exec_rmfs()


def test_archive_twice(env: TestEnv) -> None:
    env.exec_setup_fs(gsize=100)
    tds1 = env.create_data(100, "A", 2**21)
    env.exec_umount()
    arname = "ar1"
    env.exec_archive(arname)
    env.exec_rmfs()
    env.exec_restore(arname)
    env.exec_mount()
    tds1.do_read()
    tds2 = env.create_data(100, "B", 2**21)
    env.exec_umount()
    arname = "ar2"
    env.exec_archive(arname)
    env.exec_rmfs()
    env.exec_restore(arname)
    env.exec_mount()
    tds1.do_read()
    tds2.do_read()
    tds1.do_unlink()
    tds2.do_unlink()
    env.exec_umount()
    env.exec_rmfs()
