# SPDX-License-Identifier: GPL-3.0
import pathlib

from . import ctx
from . import utils


def test_postgresql(tc: ctx.TestCtx) -> None:
    url = "https://git.postgresql.org/git/postgresql.git"
    name = utils.selfname()
    tc.exec_setup_fs(8)
    base = tc.create_fstree(name)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        _test_postgresql_at(tc, base)
    tc.remove_fstree(name)
    tc.exec_umount()


def _test_postgresql_at(tc: ctx.TestCtx, base: pathlib.Path) -> None:
    tc.cmd.sh.run_ok("./configure", base)
    tc.cmd.sh.run_ok("make", base)
    tc.cmd.sh.run_ok("make check", base)
    tc.cmd.sh.run_ok("make clean", base)


def test_rsync(tc: ctx.TestCtx) -> None:
    url = "git://git.samba.org/rsync.git"
    name = utils.selfname()
    tc.exec_init()
    tc.exec_mkfs(16, sup_groups=True)
    tc.exec_mount(allow_hostids=True, writeback_cache=False)
    base = tc.create_fstree(name)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        _test_rsync_at(tc, base)
    tc.remove_fstree(name)
    tc.exec_umount()


def _test_rsync_at(tc: ctx.TestCtx, base: pathlib.Path) -> None:
    tc.cmd.sh.run_ok("./configure --disable-md2man", base)
    tc.cmd.sh.run_ok("make", base)
    tc.cmd.sh.run_ok("make check", base)
    tc.cmd.sh.run_ok("make clean", base)


def test_gitscm(tc: ctx.TestCtx) -> None:
    url = "https://github.com/git/git.git"
    name = utils.selfname()
    tc.exec_setup_fs(8)
    base = tc.create_fstree(name)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        tc.cmd.sh.run_ok("make configure", base)
        tc.cmd.sh.run_ok("./configure", base)
        tc.cmd.sh.run_ok("make", base)
        tc.cmd.sh.run_ok("make test", base)
        tc.cmd.sh.run_ok("make clean", base)
    tc.remove_fstree(name)
    tc.exec_umount()


def _test_gitscm_at(tc: ctx.TestCtx, base: pathlib.Path) -> None:
    tc.cmd.sh.run_ok("make configure", base)
    tc.cmd.sh.run_ok("./configure", base)
    tc.cmd.sh.run_ok("make", base)
    tc.cmd.sh.run_ok("make test", base)
    tc.cmd.sh.run_ok("make clean", base)
