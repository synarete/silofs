# SPDX-License-Identifier: GPL-3.0
import datetime
import pathlib
import random
import sys
import traceback

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


def _require_empty_dir(dirpath: pathlib.Path) -> None:
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


def _pre_test(tc: ctx.TestCtx) -> None:
    tc.expect.empty_dir(tc.cfg.basedir)
    tc.expect.empty_dir(tc.cfg.mntdir)


def _post_test(tc: ctx.TestCtx) -> None:
    utils.empty_dir(tc.cfg.mntdir)
    utils.empty_dir(tc.cfg.basedir)


def _exec_test(td: ctx.TestDef, tc: ctx.TestCtx) -> None:
    _print(f"TEST: {td.name}")
    td.hook(tc)


def _do_run_tests(cfg: ctx.TestConfig) -> None:
    _validate_config(cfg)
    _pre_run_tests()
    for td in test_all.get_tests_defs():
        tc = ctx.TestCtx(td.name, cfg)
        _pre_test(tc)
        _exec_test(td, tc)
        _post_test(tc)
    _post_run_tests()


def make_config(basedir: pathlib.Path, mntdir: pathlib.Path) -> ctx.TestConfig:
    _require_empty_dir(basedir)
    _require_empty_dir(mntdir)
    return ctx.TestConfig(basedir, mntdir)


def run_tests(cfg: ctx.TestConfig) -> None:
    try:
        _do_run_tests(cfg)
    except cmd.CmdError as cex:
        _print(f"FATAL: {cex} {cex.retcode}: {cex.output}")
        traceback.print_exc()
        sys.exit(1)
    except expect.ExpectException as exp:
        _print(f"FATAL: {exp}")
        traceback.print_exc()
        sys.exit(2)
