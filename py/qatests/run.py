# SPDX-License-Identifier: GPL-3.0
import datetime
import platform
import random
import sys
import traceback
from pathlib import Path

from . import conf
from . import expect
from . import log
from . import subcmd
from . import test_all
from . import utils
from .ctx import TestDef, TestEnv


class RunArgs:
    def __init__(self) -> None:
        self.start_time = datetime.datetime.now()
        self.config = conf.Config()

    def exec_duration(self) -> datetime.timedelta:
        """Returns the total time (in minutes) since start"""
        now = datetime.datetime.now()
        dif = now - self.start_time
        return datetime.timedelta(seconds=dif.total_seconds())

    def load_config(self, path: Path) -> None:
        self.config = conf.load_config(path.resolve(strict=True))


def _seed_random(args: RunArgs) -> None:
    base = args.start_time
    seed = base.year * base.day * base.hour * base.minute / (base.second + 1)
    random.seed(int(seed))


def _report_host(_: RunArgs) -> None:
    plat_sys = platform.system()
    plat_rel = platform.release()
    log.println(f"HOST: {plat_sys} {plat_rel}")
    py_impl = platform.python_implementation()
    py_vers = platform.python_version()
    log.println(f"PYTHON: {py_impl} {py_vers}")


def _report_prog(args: RunArgs) -> None:
    subcmds = subcmd.Subcmds()
    prog = subcmds.silofs.xbin
    log.println(f"PROG: {prog}")
    vers = subcmds.silofs.version()
    log.println(f"VERS: {vers}")
    log.println(f"START: {args.start_time}")


def _report_done(args: RunArgs) -> None:
    subcmds = subcmd.Subcmds()
    prog = subcmds.silofs.xbin
    vers = subcmds.silofs.version()
    log.println(f"DONE: {prog} {vers}")
    durs = args.exec_duration()
    log.println(f"DURATION: {durs}")


def _pre_run_tests(args: RunArgs) -> None:
    _seed_random(args)
    _report_host(args)
    _report_prog(args)


def _post_run_tests(args: RunArgs) -> None:
    _report_done(args)


def _pre_test(env: TestEnv) -> None:
    env.expect.empty_dir(env.cfg.basedir)
    env.expect.empty_dir(env.cfg.mntdir)


def _post_test(env: TestEnv) -> None:
    utils.empty_dir(env.cfg.mntdir)
    utils.empty_dir(env.cfg.basedir)


def _exec_test(td: TestDef, env: TestEnv) -> None:
    log.println(f"TEST: {td.name}")
    td.hook(env)


def _do_run_tests(args: RunArgs) -> None:
    _pre_run_tests(args)
    for td in test_all.get_tests_defs():
        env = TestEnv(td.name, args.config)
        _pre_test(env)
        _exec_test(td, env)
        _post_test(env)
    _post_run_tests(args)


def run_tests(args: RunArgs) -> None:
    try:
        _do_run_tests(args)
    except subcmd.SubcmdError as cex:
        log.println(f"FATAL: {cex} {cex.retcode}")
        log.println(f"FATAL: {cex.output}")
        traceback.print_exc()
        sys.exit(3)
    except expect.ExpectException as exp:
        log.println(f"FATAL: {exp}")
        traceback.print_exc()
        sys.exit(4)
