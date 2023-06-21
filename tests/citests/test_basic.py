# SPDX-License-Identifier: GPL-3.0
import os

from . import ctx


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
    os.unlink(path)
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
    wdat = tc.make_rand(2**20)
    os.mkdir(base)
    with open(path, "wb") as f:
        f.write(wdat)
    with open(path, "rb") as f:
        rdat = f.read(len(wdat))
    tc.expect.eq(wdat, rdat)
    os.unlink(path)
    os.rmdir(base)
    tc.exec_umount()


def test_show(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs()
    base = tc.make_basepath()
    os.mkdir(base)
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
    os.rmdir(base)
    tc.exec_umount()
