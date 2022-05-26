# SPDX-License-Identifier: GPL-3.0
import os

from . import cmd


class TestException(Exception):
    pass


class TestEnv:
    def __init__(self, basedir: str, mntdir: str) -> None:
        self.basedir = os.path.realpath(basedir)
        self.mntdir = os.path.relpath(mntdir)
        self.mounted = False
        self.cmd = cmd.Cmd()

    def show_version(self) -> None:
        vers = self.cmd.version()
        print(vers)
