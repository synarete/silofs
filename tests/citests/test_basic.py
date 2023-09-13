# SPDX-License-Identifier: GPL-3.0

from .ctx import TestEnv


def test_version(env: TestEnv) -> None:
    version = env.cmd.silofs.version()
    env.expect.gt(len(version), 0)


def test_init(env: TestEnv) -> None:
    env.exec_init()


def test_mkfs(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs()


def test_mount(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs()
    env.exec_mount()
    env.exec_umount()
    env.exec_rmfs()


def test_hello_world(env: TestEnv) -> None:
    env.exec_init()
    env.exec_mkfs()
    env.exec_mount()
    path = env.make_path("hello")
    data = "hello, world!"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(data)
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    env.expect.eq(len(lines), 1)
    env.expect.eq(lines[0], data)
    path.unlink()
    env.exec_umount()
    env.exec_rmfs()


def test_fscapacity(env: TestEnv) -> None:
    env.exec_init()
    _test_fscapacity(env, 2)  # minimal capacity
    _test_fscapacity(env, 256)  # normal capacity
    _test_fscapacity(env, 64 * 1024)  # maximal capacity


def _test_fscapacity(env: TestEnv, cap: int) -> None:
    name = f"{env.name}-{cap}"
    env.exec_mkfs(cap, name)
    env.exec_mount(name)
    base = env.make_path(name)
    path = env.make_path(name, "dat")
    wdat = env.make_rands(2**20)
    base.mkdir()
    path.write_bytes(wdat)
    rdat = path.read_bytes()
    env.expect.eq(wdat, rdat)
    path.unlink()
    base.rmdir()
    env.exec_umount()


def test_show(env: TestEnv) -> None:
    env.exec_setup_fs()
    base = env.make_basepath()
    base.mkdir()
    vers1 = env.cmd.silofs.version()
    env.expect.eq(len(vers1.split()), 2)
    vers2 = env.cmd.silofs.show_version(base)
    env.expect.gt(len(vers2), 1)
    env.expect.eq(vers2, vers1.split()[1])
    bsec = env.cmd.silofs.show_boot(base)
    env.expect.gt(len(bsec), 1)
    prst = env.cmd.silofs.show_proc(base)
    env.expect.gt(len(prst), 1)
    spst = env.cmd.silofs.show_spstats(base)
    env.expect.gt(len(spst), 1)
    stx = env.cmd.silofs.show_statx(base)
    env.expect.gt(len(stx), 1)
    base.rmdir()
    env.exec_teardown_fs()


def test_mkfs_mount_with_opts(env: TestEnv) -> None:
    fsname = "0123456789abcdef"
    env.exec_init()
    env.exec_mkfs(gsize=123, name=fsname, sup_groups=True, allow_root=True)
    env.exec_mount(name=fsname, allow_hostids=True, writeback_cache=False)
    tds = env.make_tds(1, "A", 2**21)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    env.exec_umount()
