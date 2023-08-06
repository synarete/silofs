# SPDX-License-Identifier: GPL-3.0

from . import ctx
from . import utils


def test_version(tc: ctx.TestCtx) -> None:
    version = tc.cmd.silofs.version()
    tc.expect.gt(len(version), 0)


def test_init(tc: ctx.TestCtx) -> None:
    tc.exec_init()


def test_mkfs(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs()


def test_mount(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs()
    tc.exec_mount()
    tc.exec_umount()


def test_hello_world(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    tc.exec_mkfs()
    tc.exec_mount()
    path = tc.make_path("hello")
    data = "hello, world!"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(data)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    tc.expect.eq(len(lines), 1)
    tc.expect.eq(lines[0], data)
    path.unlink()
    tc.exec_umount()


def test_fscapacity(tc: ctx.TestCtx) -> None:
    tc.exec_init()
    _test_fscapacity(tc, 2)  # minimal capacity
    _test_fscapacity(tc, 256)  # normal capacity
    _test_fscapacity(tc, 64 * 1024)  # maximal capacity


def _test_fscapacity(tc: ctx.TestCtx, cap: int) -> None:
    name = f"{tc.name}-{cap}"
    tc.exec_mkfs(cap, name)
    tc.exec_mount(name)
    base = tc.make_path(name)
    path = tc.make_path(name, "dat")
    wdat = utils.prandbytes(2**20)
    base.mkdir()
    path.write_bytes(wdat)
    rdat = path.read_bytes()
    tc.expect.eq(wdat, rdat)
    path.unlink()
    base.rmdir()
    tc.exec_umount()


def test_show(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    base = tc.make_basepath()
    base.mkdir()
    vers1 = tc.cmd.silofs.version()
    tc.expect.eq(len(vers1.split()), 2)
    vers2 = tc.cmd.silofs.show_version(base)
    tc.expect.gt(len(vers2), 1)
    tc.expect.eq(vers2, vers1.split()[1])
    bsec = tc.cmd.silofs.show_boot(base)
    tc.expect.gt(len(bsec), 1)
    prst = tc.cmd.silofs.show_proc(base)
    tc.expect.gt(len(prst), 1)
    spst = tc.cmd.silofs.show_spstats(base)
    tc.expect.gt(len(spst), 1)
    stx = tc.cmd.silofs.show_statx(base)
    tc.expect.gt(len(stx), 1)
    base.rmdir()
    tc.exec_umount()


def test_mkfs_mount_with_opts(tc: ctx.TestCtx) -> None:
    fsname = "0123456789abcdef"
    tc.exec_init()
    tc.exec_mkfs(gsize=123, name=fsname, sup_groups=True, allow_root=True)
    tc.exec_mount(name=fsname, allow_hostids=True, writeback_cache=False)
    tds = tc.make_tds(1, "A", 2**21)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tc.exec_umount()
