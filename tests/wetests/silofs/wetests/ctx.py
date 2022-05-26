# SPDX-License-Identifier: GPL-3.0
import os
import copy
import shutil
import typing

from . import cmd


class TestException(Exception):
    pass


# pylint: disable=R0903
class TestConfig:
    def __init__(self, basedir: str, mntdir: str) -> None:
        self.basedir = os.path.realpath(basedir)
        self.mntdir = os.path.relpath(mntdir)
        self.maindir = os.path.join(self.basedir, "main")
        self.colddir = os.path.join(self.basedir, "cold")


class TestEnv:
    def __init__(self, cfg: TestConfig) -> None:
        self.cfg = copy.copy(cfg)
        self.cmd = cmd.Cmd()
        self.mounted = False
        self.tag = ""

    def do_init(self) -> None:
        self.cmd.init(self.cfg.maindir)

    def do_mkfs(self, name: str, gsize: int = 2):
        repodir_name = os.path.join(self.cfg.maindir, name)
        gibi = 2**30
        size = gsize * gibi
        self.cmd.mkfs(repodir_name, size)

    def error(self, msg: str) -> None:
        raise TestException(self.tag + msg)

    def expect_len(self, dat: typing.Sized) -> None:
        if len(dat) == 0:
            self.error("empty {}".format(dat))

    def expect_dir(self, dirpath: str) -> None:
        if not os.path.isdir(dirpath):
            self.error("not a directory {}".format(dirpath))

    def expect_emptydir(self, dirpath: str) -> None:
        self.expect_dir(dirpath)
        if os.listdir(dirpath):
            self.error("not an empty directory {}".format(dirpath))

    def emptydir(self, dirpath: str) -> None:
        self.expect_dir(dirpath)
        for name in os.listdir(dirpath):
            subpath = os.path.join(dirpath, name)
            if os.path.isdir(subpath):
                shutil.rmtree(subpath)
            else:
                os.remove(subpath)


class TestDef:
    def __init__(self, hook: typing.Callable[[TestEnv], None]) -> None:
        mod = "." + hook.__module__
        self.hook = hook
        self.name = "{}.{}".format(mod.split(".")[-1], hook.__name__)
