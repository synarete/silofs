# SPDX-License-Identifier: GPL-3.0
import pathlib

from . import ctx


def test_unitests(tc: ctx.TestCtx) -> None:
    ut_pre_dname = "pre-uniests"
    ut_dname = "unitests"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(128, ut_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ut_root = tc.create_fstree(ut_dname)
    tc.cmd.unitests.version()
    tc.cmd.unitests.run(ut_root, level=2)
    tc.remove_fstree(ut_dname)
    tds.do_read()
    tds.do_unlink()
    tc.remove_fstree(ut_pre_dname)
    tc.exec_teardown_fs()


def test_fftests(tc: ctx.TestCtx) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname = "fftests"
    ff_snap_name = "fftests-snap"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(64, ff_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    ff_root = tc.create_fstree(ff_dname)
    tc.cmd.fftests.version()
    tc.cmd.fftests.run(ff_root, False)
    tc.exec_snap(ff_snap_name)
    tds.do_read()
    tc.cmd.fftests.run(ff_root, True)
    tds.do_read()
    tds.do_unlink()
    tc.remove_fstree(ff_pre_dname)
    tc.remove_fstree(ff_dname)
    tc.exec_umount()
    tc.exec_rmfs(ff_snap_name)


def test_fftests2(tc: ctx.TestCtx) -> None:
    ff_dname = "fftests2"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(64, ff_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    ff_root = tc.create_fstree(ff_dname)
    tc.exec_tune2([ff_root])
    tc.cmd.fftests.version()
    tc.cmd.fftests.run(ff_root)
    tc.remove_fstree(ff_dname)
    tc.exec_teardown_fs()


def run_fftests(tc: ctx.TestCtx, base: pathlib.Path, rand: bool) -> None:
    tc.cmd.fftests.run(base, rand, True)


def test_fftests_mt(tc: ctx.TestCtx) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname1 = "fftests1"
    ff_dname2 = "fftests2"
    ff_snap_name1 = "fftests-snap1"
    ff_snap_name2 = "fftests-snap2"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(32, ff_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ff_root1 = tc.create_fstree(ff_dname1)
    ff_root2 = tc.create_fstree(ff_dname2)
    fu1 = tc.executor.submit(run_fftests, tc, ff_root1, True)
    fu2 = tc.executor.submit(run_fftests, tc, ff_root2, False)
    tc.exec_snap(ff_snap_name1)
    tds.do_read()
    tc.suspend(2)
    tc.exec_snap(ff_snap_name2)
    tds.do_read()
    fu1.result()
    fu2.result()
    tds.do_unlink()
    tc.remove_fstree(ff_pre_dname)
    tc.remove_fstree(ff_dname1)
    tc.remove_fstree(ff_dname2)
    tc.exec_umount()
    tc.exec_rmfs(ff_snap_name1)
    tc.exec_rmfs(ff_snap_name2)
