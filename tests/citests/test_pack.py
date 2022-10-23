# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_pack_simple(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs(8)
    tds = tc.make_tds(16, "A", 2**20)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    name1 = "fs1"
    tc.exec_snap(name1)
    tc.exec_umount()
    arname = "archive"
    tc.exec_archive(name1, arname)
    name2 = "fs2"
    tc.exec_restore(arname, name2)
    tc.exec_mount(name2)
    tds.do_read()
    tc.exec_umount()


def test_pack_multi(tc: ctx.TestCtx) -> None:
    ar_map = {}
    fs_name = tc.name
    tc.exec_setup_fs(100)
    for n in range(1, 10):
        snap_name = f"{fs_name}-snap-{n}"
        archive_name = f"{fs_name}-archive-{n}"
        tds = tc.make_tds(100, f"{fs_name}-{n}", 2**20)
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        tc.exec_snap(snap_name)
        archive_name = f"{fs_name}-archive-{n}"
        tc.exec_archive(snap_name, archive_name)
        ar_map[archive_name] = tds
    tc.exec_umount()
    for archive_name, tds in ar_map.items():
        restore_name = archive_name.replace("archive", "restore")
        tc.exec_restore(archive_name, restore_name)
        tc.exec_mount(restore_name)
        tds.do_stat()
        tds.do_read()
        tds2 = tc.make_tds(100, restore_name, 2**20)
        tds2.do_makedirs()
        tds2.do_write()
        tds2.do_read()
        tds.do_read()
        tds.do_unlink()
        tds2.do_unlink()
        tc.exec_umount()
