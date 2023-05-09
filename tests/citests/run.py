# SPDX-License-Identifier: GPL-3.0
import sys
import os
import traceback
from . import expect
from . import cmd
from . import ctx
from . import utils
from . import test_all


def _die(msg: str) -> None:
    print(msg)
    sys.exit(1)


def _require_empty_dir(dirpath: str) -> None:
    if not os.path.isdir(dirpath):
        _die(f"not a directory: {dirpath}")
    if os.listdir(dirpath):
        _die(f"not an empty directory: {dirpath}")


def _validate_config(cfg: ctx.TestConfig) -> None:
    _require_empty_dir(cfg.basedir)
    _require_empty_dir(cfg.mntdir)


def _report_prog() -> None:
    cmds = cmd.Cmds()
    prog = cmds.silofs.xbin
    vers = cmds.silofs.version()
    print(f"PROG: {prog}")
    print(f"VERS: {vers}")


def _pre_run_tests() -> None:
    _report_prog()


def _post_run_tests() -> None:
    pass


def _pre_test(tc: ctx.TestCtx) -> None:
    tc.expect.empty_dir(tc.cfg.basedir)
    tc.expect.empty_dir(tc.cfg.mntdir)


def _post_test(tc: ctx.TestCtx) -> None:
    utils.empty_dir(tc.cfg.mntdir)
    utils.empty_dir(tc.cfg.basedir)


def _exec_test(td: ctx.TestDef, tc: ctx.TestCtx) -> None:
    print(f"TEST: {td.name}")
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


def run_tests(cfg: ctx.TestConfig) -> None:
    try:
        _do_run_tests(cfg)
    except cmd.CmdError as cex:
        print(f"FATAL: {cex} {cex.retcode}: {cex.output}")
        traceback.print_exc()
        sys.exit(1)
    except expect.ExpectException as exp:
        print(f"FATAL: {exp}")
        traceback.print_exc()
        sys.exit(2)
