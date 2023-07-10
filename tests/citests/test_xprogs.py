# SPDX-License-Identifier: GPL-3.0
import os
import shutil

from . import ctx


def test_postgresql(tc: ctx.TestCtx) -> None:
    url = "https://git.postgresql.org/git/postgresql.git"
    tc.exec_setup_fs(8)
    base = tc.make_path("postgresql")
    os.mkdir(base)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        tc.cmd.sh.run_ok("./configure", base)
        tc.cmd.sh.run_ok("make", base)
        tc.cmd.sh.run_ok("make check", base)
        tc.cmd.sh.run_ok("make clean", base)
    shutil.rmtree(base)
    tc.exec_umount()


def test_rsync(tc: ctx.TestCtx) -> None:
    url = "git://git.samba.org/rsync.git"
    tc.exec_init()
    tc.exec_mkfs(16, sup_groups=True)
    tc.exec_mount(allow_hostids=True, writeback_cache=False)
    base = tc.make_path("rsync")
    os.mkdir(base)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        tc.cmd.sh.run_ok("./configure --disable-md2man", base)
        tc.cmd.sh.run_ok("make", base)
        tc.cmd.sh.run_ok("make check", base)
        tc.cmd.sh.run_ok("make clean", base)
    shutil.rmtree(base)
    tc.exec_umount()


def test_gitscm(tc: ctx.TestCtx) -> None:
    url = "https://github.com/git/git.git"
    tc.exec_setup_fs(8)
    base = tc.make_path("git-scm")
    os.mkdir(base)
    ret = tc.cmd.git.clone(url, base)
    if ret == 0:
        tc.cmd.sh.run_ok("make configure", base)
        tc.cmd.sh.run_ok("./configure", base)
        tc.cmd.sh.run_ok("make", base)
        tc.cmd.sh.run_ok("make test", base)
        tc.cmd.sh.run_ok("make clean", base)
    shutil.rmtree(base)
    tc.exec_umount()
