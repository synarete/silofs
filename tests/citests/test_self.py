# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_unit_tests(tc: ctx.TestCtx) -> None:
    dname1 = "pre-unit-tests"
    dname2 = "unit-tests"
    tc.exec_setup_fs(64)
    tds = tc.make_tds(128, dname1, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ut_root = tc.do_mkdirs(dname2)
    tc.cmd.unitests.version()
    tc.cmd.unitests.run(ut_root, level=2)
    tc.do_rmtree(dname2)
    tds.do_read()
    tds.do_unlink()
    tc.do_rmtree(dname1)
    tc.exec_umount()


def test_vfs_tests(tc: ctx.TestCtx) -> None:
    dname1 = "pre-vfs-tests"
    dname2 = "vfs-tests"
    snap_name = "vfs-tests-snap"
    tc.exec_setup_fs(64)
    tds = tc.make_tds(64, dname1, 2**22)
    tds.do_makedirs()
    tds.do_write()
    vt_root = tc.do_mkdirs(dname2)
    tc.cmd.vfstests.version()
    tc.cmd.vfstests.run(vt_root, False)
    tc.exec_snap(snap_name)
    tds.do_read()
    tc.cmd.vfstests.run(vt_root, True)
    tds.do_read()
    tds.do_unlink()
    tc.do_rmtree(dname1)
    tc.do_rmtree(dname2)
    tc.exec_umount()
    tc.exec_rmfs(snap_name)
