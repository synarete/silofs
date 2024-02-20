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


def test_funtests(env: TestEnv) -> None:
    ff_pre_dname = "pre-funtests"
    ff_dname = "funtests"
    ff_snap_name = "funtests-snap"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(64, ff_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    ff_root = env.create_fstree(ff_dname)
    env.cmd.funtests.version()
    env.cmd.funtests.run(ff_root, False)
    env.exec_snap(ff_snap_name)
    tds.do_read()
    env.cmd.funtests.run(ff_root, True)
    tds.do_read()
    tds.do_unlink()
    env.remove_fstree(ff_pre_dname)
    env.remove_fstree(ff_dname)
    env.exec_umount()
    env.exec_rmfs(ff_snap_name)


def test_funtests2(env: TestEnv) -> None:
    ff_dname = "funtests2"
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
    env.cmd.funtests.version()
    env.cmd.funtests.run(ff_root)
    env.remove_fstree(ff_dname)
    env.exec_teardown_fs()


def run_funtests(env: TestEnv, base: Path, rand: bool) -> None:
    env.cmd.funtests.run(base, rand, True)


def test_funtests_mt(env: TestEnv) -> None:
    ff_pre_dname = "pre-funtests"
    ff_dname1 = "funtests1"
    ff_dname2 = "funtests2"
    ff_snap_name1 = "funtests-snap1"
    ff_snap_name2 = "funtests-snap2"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(32, ff_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ff_root1 = env.create_fstree(ff_dname1)
    ff_root2 = env.create_fstree(ff_dname2)
    fu1 = env.executor.submit(run_funtests, env, ff_root1, True)
    fu2 = env.executor.submit(run_funtests, env, ff_root2, False)
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
