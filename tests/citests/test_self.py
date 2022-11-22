# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_unit_tests(tc: ctx.TestCtx) -> None:
    ut_pre_dname = "pre-unit-tests"
    ut_dname = "unit-tests"
    tc.exec_setup_fs(64)
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


def test_vfs_tests(tc: ctx.TestCtx) -> None:
    vt_pre_dname = "pre-vfs-tests"
    vt_dname = "vfs-tests"
    vt_snap_name = "vfs-tests-snap"
    tc.exec_setup_fs(64)
    tds = tc.make_tds(64, vt_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    vt_root = tc.do_mkdirs(vt_dname)
    tc.cmd.vfstests.version()
    tc.cmd.vfstests.run(vt_root, False)
    tc.exec_snap(vt_snap_name)
    tds.do_read()
    tc.cmd.vfstests.run(vt_root, True)
    tds.do_read()
    tds.do_unlink()
    tc.do_rmtree(vt_pre_dname)
    tc.do_rmtree(vt_dname)
    tc.exec_umount()
    tc.exec_rmfs(vt_snap_name)


def test_vfs_tests2(tc: ctx.TestCtx) -> None:
    vt_pre_dname = "pre-vfs-tests"
    vt_dname1 = "vfs-tests1"
    vt_dname2 = "vfs-tests2"
    vt_snap_name1 = "vfs-tests-snap1"
    vt_snap_name2 = "vfs-tests-snap2"
    tc.exec_setup_fs(64)
    tds = tc.make_tds(32, vt_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    vt_root1 = tc.do_mkdirs(vt_dname1)
    vt_root2 = tc.do_mkdirs(vt_dname2)
    th1 = tc.cmd.vfstests.make_thread(vt_root1, True, True)
    th2 = tc.cmd.vfstests.make_thread(vt_root2, True, True)
    th1.start()
    th2.start()
    tc.exec_snap(vt_snap_name1)
    tds.do_read()
    tc.suspend(2)
    tc.exec_snap(vt_snap_name2)
    tds.do_read()
    th1.join()
    th2.join()
    tds.do_unlink()
    tc.do_rmtree(vt_pre_dname)
    tc.do_rmtree(vt_dname1)
    tc.do_rmtree(vt_dname2)
    tc.exec_umount()
    tc.exec_rmfs(vt_snap_name1)
    tc.exec_rmfs(vt_snap_name2)
