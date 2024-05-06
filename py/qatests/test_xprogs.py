# SPDX-License-Identifier: GPL-3.0
from pathlib import Path

from . import utils
from .ctx import TestEnv


def test_postgresql(env: TestEnv) -> None:
    url = env.cfg.remotes.postgresql_repo_url
    if not url:
        return
    name = env.uniq_name()
    env.exec_setup_fs(20)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_postgresql_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_postgresql_at(env: TestEnv, base: Path) -> None:
    env.cmd.sh.run_ok("./configure", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make check", base)
    env.cmd.sh.run_ok("make clean", base)


def test_rsync(env: TestEnv) -> None:
    url = env.cfg.remotes.rsync_repo_url
    if not url:
        return
    name = env.uniq_name()
    env.exec_init()
    env.exec_mkfs(20, sup_groups=True)
    env.exec_mount(
        allow_hostids=True,
        allow_xattr_acl=False,
        writeback_cache=False,
    )
    env.exec_lsmnt()
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_rsync_at(env, base)
    env.remove_fstree(name)
    env.exec_umount()


def _test_rsync_at(env: TestEnv, base: Path) -> None:
    env.cmd.sh.run_ok("./configure --disable-md2man", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make check", base)
    env.cmd.sh.run_ok("make clean", base)


def test_gitscm(env: TestEnv) -> None:
    url = env.cfg.remotes.git_repo_url
    if not url:
        return
    name = env.uniq_name()
    env.exec_setup_fs(8)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_gitscm_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_gitscm_at(env: TestEnv, base: Path) -> None:
    env.cmd.sh.run_ok("make configure", base)
    env.cmd.sh.run_ok("./configure", base)
    env.cmd.sh.run_ok("make", base)
    env.cmd.sh.run_ok("make test", base)
    env.cmd.sh.run_ok("make clean", base)


def test_git_archive_untar(env: TestEnv) -> None:
    url = env.cfg.remotes.silofs_repo_url
    if not url:
        return
    name = env.uniq_name()
    env.exec_setup_fs(60)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    if ret == 0:
        _test_git_archive_untar_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_git_archive_untar_at(env: TestEnv, base: Path) -> None:
    prefix = "archive-head/"
    tarname = "archive-head.tar.gz"
    out = base / tarname
    fmt = "tar.gz"
    cmd = f"git archive --output={out} --prefix={prefix} --format={fmt} HEAD"
    env.cmd.sh.run_ok(cmd, base)
    cmd = f"tar xvf {tarname}"
    env.cmd.sh.run_ok(cmd, base)


def test_rpmbuild(env: TestEnv) -> None:
    url = env.cfg.remotes.silofs_repo_url
    if not url:
        return
    name = env.uniq_name()
    env.exec_setup_fs(20)
    base = env.create_fstree(name)
    ret = env.cmd.git.clone(url, base)
    ok = utils.has_executables(["make", "rpmbuild"])
    if ok and ret == 0:
        _test_rpmbuild_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_rpmbuild_at(env: TestEnv, base: Path) -> None:
    env.cmd.sh.run_ok("make -f devel.mk rpm", base)
    env.cmd.sh.run_ok("make -f devel.mk reset", base)
