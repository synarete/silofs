# SPDX-License-Identifier: GPL-3.0

from pathlib import Path

from . import utils
from .ctx import TestEnv


def test_utests(env: TestEnv) -> None:
    ut_pre_dname = "pre-uniests"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(128, ut_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ut_dname = "utests"
    ut_root = env.create_fstree(ut_dname)
    env.subcmd.utests.version()
    env.subcmd.utests.run(ut_root, level=2)
    env.remove_fstree(ut_dname)
    ut_dname = "utests-malloc"
    ut_root = env.create_fstree(ut_dname)
    env.subcmd.utests.version()
    env.subcmd.utests.run(ut_root, level=2, malloc=True)
    env.remove_fstree(ut_dname)
    tds.do_read()
    tds.do_unlink()
    env.remove_fstree(ut_pre_dname)
    env.exec_teardown_fs()


def test_ftests(env: TestEnv) -> None:
    ff_pre_dname = "pre-ftests"
    ff_dname = "ftests"
    ff_fork_name = "ftests-fork"
    env.exec_setup_fs(64, allow_xattr_acl=True, writeback_cache=False)
    tds = env.make_tds(64, ff_pre_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    ff_root = env.create_fstree(ff_dname)
    env.subcmd.ftests.version()
    env.subcmd.ftests.run(ff_root, rand=False)
    env.exec_fork(ff_fork_name)
    tds.do_read()
    env.subcmd.ftests.run(ff_root, rand=True)
    tds.do_read()
    tds.do_unlink()
    env.exec_rmfs(ff_fork_name)
    env.remove_fstree(ff_pre_dname)
    env.remove_fstree(ff_dname)
    env.exec_teardown_fs()


def test_ftests_nosplice(env: TestEnv) -> None:
    ff_dname = "ftests_nosplice"
    env.exec_init()
    env.exec_mkfs(40)
    env.exec_mount(writeback_cache=False, buffer_copy_mode=True)
    tds = env.make_tds(40, ff_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    tds.do_unlink()
    tds.do_rmdirs()
    ff_root = env.create_fstree(ff_dname)
    env.subcmd.ftests.run(ff_root)
    env.remove_fstree(ff_dname)
    env.exec_teardown_fs()


def test_ftests_tune2(env: TestEnv) -> None:
    ff_dname = "ftests2"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(64, ff_dname, 2**22)
    tds.do_makedirs()
    tds.do_write()
    tds.do_read()
    tds.do_write()
    tds.do_read()
    tds.do_unlink()
    tds.do_rmdirs()
    ff_root = env.create_fstree(ff_dname)
    env.exec_tune2([ff_root])
    env.subcmd.ftests.version()
    env.subcmd.ftests.run(ff_root)
    env.remove_fstree(ff_dname)
    env.exec_teardown_fs()


def _run_ftests(env: TestEnv, base: Path) -> None:
    env.subcmd.ftests.run(base, rand=True, nostatvfs=True, noflaky=True)


def test_ftests_mt(env: TestEnv) -> None:
    ff_pre_dname = "pre-ftests"
    ff_dname1 = "ftests1"
    ff_dname2 = "ftests2"
    ff_fork_name1 = "ftests-fork1"
    ff_fork_name2 = "ftests-fork2"
    env.exec_setup_fs(64, writeback_cache=False)
    tds = env.make_tds(32, ff_pre_dname, 2**20)
    tds.do_makedirs()
    tds.do_write()
    ff_root1 = env.create_fstree(ff_dname1)
    ff_root2 = env.create_fstree(ff_dname2)
    fu1 = env.executor.submit(_run_ftests, env, ff_root1)
    fu2 = env.executor.submit(_run_ftests, env, ff_root2)
    env.exec_fork(ff_fork_name1)
    tds.do_read()
    env.suspend(2)
    env.exec_fork(ff_fork_name2)
    tds.do_read()
    fu1.result()
    fu2.result()
    tds.do_unlink()
    env.remove_fstree(ff_pre_dname)
    env.remove_fstree(ff_dname1)
    env.remove_fstree(ff_dname2)
    env.exec_rmfs(ff_fork_name1)
    env.exec_rmfs(ff_fork_name2)
    env.exec_teardown_fs()


def _is_active_url(url: str) -> bool:
    if not url:
        return False
    if url.startswith("http") and not utils.try_urlread_some(url):
        return False
    return True


def test_local_cicd(env: TestEnv) -> None:
    url = env.cfg.remotes.silofs_repo_url
    if _is_active_url(url):
        _test_local_cicd(env)


def _test_local_cicd(env: TestEnv) -> None:
    url = env.cfg.remotes.silofs_repo_url
    name = env.uniq_name()
    env.exec_setup_fs(60)
    base = env.create_fstree(name)
    ret = env.subcmd.git.clone(url, base, branch="next")
    if ret == 0:
        _test_local_cicd_at(env, base)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _test_local_cicd_at(env: TestEnv, base: Path) -> None:
    cicd_dir = base / "cicd"
    env.subcmd.sh.run_ok("./run-local-cicd.sh", cicd_dir)
