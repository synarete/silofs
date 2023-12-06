# SPDX-License-Identifier: GPL-3.0

from pathlib import Path

from .ctx import TestEnv


def test_unitests(env: TestEnv) -> None:
    ut_pre_dname = "pre-uniests"
    ut_dname = "unitests"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(128, ut_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ut_root = env.create_fstree(ut_dname)
    env.cmd.unitests.version()
    env.cmd.unitests.run(ut_root, level=2)
    env.remove_fstree(ut_dname)
    tds.do_read()
    tds.do_unlink()
    env.remove_fstree(ut_pre_dname)
    env.exec_teardown_fs()


def test_fftests(env: TestEnv) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname = "fftests"
    ff_snap_name = "fftests-snap"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(64, ff_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    ff_root = env.create_fstree(ff_dname)
    env.cmd.fftests.version()
    env.cmd.fftests.run(ff_root, False)
    env.exec_snap(ff_snap_name)
    tds.do_read()
    env.cmd.fftests.run(ff_root, True)
    tds.do_read()
    tds.do_unlink()
    env.remove_fstree(ff_pre_dname)
    env.remove_fstree(ff_dname)
    env.exec_umount()
    env.exec_rmfs(ff_snap_name)


def test_fftests2(env: TestEnv) -> None:
    ff_dname = "fftests2"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(64, ff_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    ff_root = env.create_fstree(ff_dname)
    env.exec_tune2([ff_root])
    env.cmd.fftests.version()
    env.cmd.fftests.run(ff_root)
    env.remove_fstree(ff_dname)
    env.exec_teardown_fs()


def run_fftests(env: TestEnv, base: Path, rand: bool) -> None:
    env.cmd.fftests.run(base, rand, True)


def test_fftests_mt(env: TestEnv) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname1 = "fftests1"
    ff_dname2 = "fftests2"
    ff_snap_name1 = "fftests-snap1"
    ff_snap_name2 = "fftests-snap2"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(32, ff_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ff_root1 = env.create_fstree(ff_dname1)
    ff_root2 = env.create_fstree(ff_dname2)
    fu1 = env.executor.submit(run_fftests, env, ff_root1, True)
    fu2 = env.executor.submit(run_fftests, env, ff_root2, False)
    env.exec_snap(ff_snap_name1)
    tds.do_read()
    env.suspend(2)
    env.exec_snap(ff_snap_name2)
    tds.do_read()
    fu1.result()
    fu2.result()
    tds.do_unlink()
    env.remove_fstree(ff_pre_dname)
    env.remove_fstree(ff_dname1)
    env.remove_fstree(ff_dname2)
    env.exec_umount()
    env.exec_rmfs(ff_snap_name1)
    env.exec_rmfs(ff_snap_name2)
