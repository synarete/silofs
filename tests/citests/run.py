# SPDX-License-Identifier: GPL-3.0
import datetime
import random
import sys
import traceback
from pathlib import Path

from . import cmd
from . import ctx
from . import expect
from . import log
from . import test_all
from . import utils


def _die(msg: str) -> None:
    log.println(msg)
    sys.exit(1)


def _print(msg: str) -> None:
    log.println(msg)


def _require_empty_dir(dirpath: Path) -> None:
    if not utils.is_dir(dirpath):
        _die(f"not a directory: {dirpath}")
    if not utils.is_empty_dir(dirpath):
        _die(f"not an empty directory: {dirpath}")


def _validate_config(cfg: ctx.TestConfig) -> None:
    _require_empty_dir(cfg.basedir)
    _require_empty_dir(cfg.mntdir)


def _seed_random() -> None:
    now = datetime.datetime.now()
    seed = int(now.year * now.day * now.hour * now.minute / (now.second + 1))
    random.seed(seed)


def _report_prog() -> None:
    cmds = cmd.Cmds()
    prog = cmds.silofs.xbin
    _print(f"PROG: {prog}")
    vers = cmds.silofs.version()
    _print(f"VERS: {vers}")


def _report_done() -> None:
    cmds = cmd.Cmds()
    prog = cmds.silofs.xbin
    vers = cmds.silofs.version()
    _print(f"DONE: {prog} {vers}")


def _pre_run_tests() -> None:
    _seed_random()
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
    _print(f"TEST: {td.name}")
    td.hook(env)


def _do_run_tests(cfg: ctx.TestConfig) -> None:
    _validate_config(cfg)
    _pre_run_tests()
    for td in test_all.get_tests_defs():
        env = ctx.TestEnv(td.name, cfg)
        _pre_test(env)
        _exec_test(td, env)
        _post_test(env)
    _post_run_tests()


def make_config(basedir: Path, mntdir: Path) -> ctx.TestConfig:
    _require_empty_dir(basedir)
    _require_empty_dir(mntdir)
    return ctx.TestConfig(basedir, mntdir)


def run_tests(cfg: ctx.TestConfig) -> None:
    try:
        _do_run_tests(cfg)
    except cmd.CmdError as cex:
        _print(f"FATAL: {cex} {cex.retcode}")
        _print(f"FATAL: {cex.output}")
        traceback.print_exc()
        sys.exit(1)
    except expect.ExpectException as exp:
        _print(f"FATAL: {exp}")
        traceback.print_exc()
        sys.exit(2)
