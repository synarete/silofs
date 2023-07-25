# SPDX-License-Identifier: GPL-3.0
import pathlib

from . import ctx


def test_unit_tests(tc: ctx.TestCtx) -> None:
    ut_pre_dname = "pre-unit-tests"
    ut_dname = "unit-tests"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(128, ut_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ut_root = tc.do_mkdirs(ut_dname)
    tc.cmd.unitests.version()
    tc.cmd.unitests.run(ut_root, level=2)
    tc.do_rmtree(ut_dname)
    tds.do_read()
    tds.do_unlink()
    tc.do_rmtree(ut_pre_dname)
    tc.exec_umount()


def test_func_tests(tc: ctx.TestCtx) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname = "fftests"
    ff_snap_name = "fftests-snap"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(64, ff_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    ff_root = tc.do_mkdirs(ff_dname)
    tc.cmd.fftests.version()
    tc.cmd.fftests.run(ff_root, False)
    tc.exec_snap(ff_snap_name)
    tds.do_read()
    tc.cmd.fftests.run(ff_root, True)
    tds.do_read()
    tds.do_unlink()
    tc.do_rmtree(ff_pre_dname)
    tc.do_rmtree(ff_dname)
    tc.exec_umount()
    tc.exec_rmfs(ff_snap_name)


def run_fftests(tc: ctx.TestCtx, base: pathlib.Path, rand: bool) -> None:
    tc.cmd.fftests.run(base, rand, True)


def test_func_tests2(tc: ctx.TestCtx) -> None:
    ff_pre_dname = "pre-fftests"
    ff_dname1 = "fftests1"
    ff_dname2 = "fftests2"
    ff_snap_name1 = "fftests-snap1"
    ff_snap_name2 = "fftests-snap2"
    tc.exec_setup_fs(64, writeback_cache=False)
    tds = tc.make_tds(32, ff_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ff_root1 = tc.do_mkdirs(ff_dname1)
    ff_root2 = tc.do_mkdirs(ff_dname2)
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
    tc.do_rmtree(ff_pre_dname)
    tc.do_rmtree(ff_dname1)
    tc.do_rmtree(ff_dname2)
    tc.exec_umount()
    tc.exec_rmfs(ff_snap_name1)
    tc.exec_rmfs(ff_snap_name2)
