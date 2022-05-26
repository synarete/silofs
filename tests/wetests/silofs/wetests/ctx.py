# SPDX-License-Identifier: GPL-3.0
import os
import copy
import typing

from . import cmd
from . import fsutils


class TestException(Exception):
    pass


# pylint: disable=R0903
class TestConfig:
    def __init__(self, basedir: str, mntdir: str) -> None:
        self.basedir = os.path.realpath(basedir)
        self.mntdir = os.path.realpath(mntdir)
        self.maindir = os.path.join(self.basedir, "main")
        self.colddir = os.path.join(self.basedir, "cold")


class TestExp:
    def __init__(self) -> None:
        self.set_label("")

    def set_label(self, label: str) -> None:
        self.label = label

    def error(self, msg: str) -> typing.NoReturn:
        prefix = ""
        if self.label:
            prefix = self.label + ": "
        raise TestException(prefix + msg)

    def expect_eq(self, a, b) -> None:
        if a != b:
            self.error("{} != {}".format(a, b))

    def expect_gt(self, a, b) -> None:
        if a <= b:
            self.error("{} <= {}".format(a, b))

    def expect_dir(self, dirpath: str) -> None:
        if not fsutils.is_dir(dirpath):
            self.error("not a directory {}".format(dirpath))

    def expect_empty_dir(self, dirpath: str) -> None:
        if not fsutils.is_empty_dir(dirpath):
            self.error("not an empty directory {}".format(dirpath))


class TestEnv(TestExp):
    def __init__(self, cfg: TestConfig) -> None:
        TestExp.__init__(self)
        self.cfg = copy.copy(cfg)
        self.cmd = cmd.Cmd()
        self.mounted = False

    def do_init(self) -> None:
        self.cmd.init(self.cfg.maindir)

    def do_mkfs(self, name: str, gsize: int = 2):
        gibi = 2**30
        size = gsize * gibi
        self.cmd.mkfs(self._repodir_name(name), size)

    def do_mount(self, name: str) -> None:
        self.cmd.mount(self._repodir_name(name), self.cfg.mntdir)

    def do_umount(self) -> None:
        self.cmd.umount(self.cfg.mntdir)

    def _repodir_name(self, name: str) -> str:
        return os.path.join(self.cfg.maindir, name)


class TestDef:
    def __init__(self, hook: typing.Callable[[TestEnv], None]) -> None:
        mod = "." + hook.__module__
        self.hook = hook
        self.name = "{}.{}".format(mod.split(".")[-1], hook.__name__)
