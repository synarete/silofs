# SPDX-License-Identifier: GPL-3.0
import pathlib

from .ctx import TestEnv


def test_postgresql(env: TestEnv) -> None:
    url = "https://git.postgresql.org/git/postgresql.git"
    name = env.uniq_name()
    env.exec_setup_fs(8)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_postgresql_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_postgresql_at(env: TestEnv, base: pathlib.Path) -> None:
    env.cmd.sh.run_ok("./configure", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make check", base)
    env.cmd.sh.run_ok("make clean", base)


def test_rsync(env: TestEnv) -> None:
    url = "git://git.samba.org/rsync.git"
    name = env.uniq_name()
    env.exec_init()
    env.exec_mkfs(16, sup_groups=True)
    env.exec_mount(allow_hostids=True, writeback_cache=False)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_rsync_at(env, base)
    env.remove_fstree(name)
    env.exec_umount()


def _test_rsync_at(env: TestEnv, base: pathlib.Path) -> None:
    env.cmd.sh.run_ok("./configure --disable-md2man", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make check", base)
    env.cmd.sh.run_ok("make clean", base)


def test_gitscm(env: TestEnv) -> None:
    url = "https://github.com/git/git.git"
    name = env.uniq_name()
    env.exec_setup_fs(8)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_gitscm_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_gitscm_at(env: TestEnv, base: pathlib.Path) -> None:
    env.cmd.sh.run_ok("make configure", base)
    env.cmd.sh.run_ok("./configure", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make test", base)
    env.cmd.sh.run_ok("make clean", base)
