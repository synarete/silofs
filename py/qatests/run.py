# SPDX-License-Identifier: GPL-3.0
import datetime
import platform
import random
import sys
import traceback

from . import cmd
from . import conf
from . import ctx
from . import expect
from . import log
from . import test_all
from . import utils


def _seed_random() -> None:
    now = datetime.datetime.now()
    seed = int(now.year * now.day * now.hour * now.minute / (now.second + 1))
    random.seed(seed)


def _report_host() -> None:
    plat_sys = platform.system()
    plat_rel = platform.release()
    log.println(f"HOST: {plat_sys} {plat_rel}")
    py_impl = platform.python_implementation()
    py_vers = platform.python_version()
    log.println(f"PYTHON: {py_impl} {py_vers}")


def _report_prog() -> None:
    cmds = cmd.Cmds()
    prog = cmds.silofs.xbin
    log.println(f"PROG: {prog}")
    vers = cmds.silofs.version()
    log.println(f"VERS: {vers}")


def _report_done() -> None:
    cmds = cmd.Cmds()
    prog = cmds.silofs.xbin
    vers = cmds.silofs.version()
    log.println(f"DONE: {prog} {vers}")


def _pre_run_tests() -> None:
    _seed_random()
    _report_host()
    _report_prog()


def _post_run_tests() -> None:
    _report_done()


def _pre_test(env: ctx.TestEnv) -> None:
    env.expect.empty_dir(env.cfg.basedir)
    env.expect.empty_dir(env.cfg.mntdir)


def _post_test(env: ctx.TestEnv) -> None:
    utils.empty_dir(env.cfg.mntdir)
    utils.empty_dir(env.cfg.basedir)


def _exec_test(td: ctx.TestDef, env: ctx.TestEnv) -> None:
    log.println(f"TEST: {td.name}")
    td.hook(env)


def _do_run_tests(cfg: conf.TestConfig) -> None:
    _pre_run_tests()
    for td in test_all.get_tests_defs():
        env = ctx.TestEnv(td.name, cfg)
        _pre_test(env)
        _exec_test(td, env)
        _post_test(env)
    _post_run_tests()


def run_tests(cfg: conf.TestConfig) -> None:
    try:
        _do_run_tests(cfg)
    except cmd.CmdError as cex:
        log.println(f"FATAL: {cex} {cex.retcode}")
        log.println(f"FATAL: {cex.output}")
        traceback.print_exc()
        sys.exit(3)
    except expect.ExpectException as exp:
        log.println(f"FATAL: {exp}")
        traceback.print_exc()
        sys.exit(4)
