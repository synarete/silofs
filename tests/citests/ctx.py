# SPDX-License-Identifier: GPL-3.0
import os
import copy
import typing
import random
import datetime
import shutil
import time

from . import cmd
from . import expect


class TestException(Exception):
    pass


# pylint: disable=R0903
class TestConfig:
    def __init__(self, basedir: str, mntdir: str) -> None:
        self.basedir = os.path.realpath(basedir)
        self.mntdir = os.path.realpath(mntdir)
        self.repodir = os.path.join(self.basedir, "repo")


# pylint: disable=R0903
class TestData:
    def __init__(self, path: str, data: bytes) -> None:
        self.path = path
        self.data = data
        self.base = 0

    def fsize(self) -> int:
        return self.base + len(self.data)


class TestDataSet:
    def __init__(self, exp: expect.Expect, tds: list[TestData]) -> None:
        self.expect = exp
        self.tds = tds

    def do_makedirs(self) -> None:
        for td in self.tds:
            dpath = os.path.dirname(td.path)
            os.makedirs(dpath, exist_ok=True)
            self.expect.is_dir(dpath)

    def do_write(self) -> None:
        for td in self.tds:
            with open(td.path, "wb") as f:
                f.write(td.data)
                self.expect.is_reg(td.path)

    def do_read(self) -> None:
        for td in self.tds:
            with open(td.path, "rb") as f:
                rdat = f.read(len(td.data))
                self.expect.eq(rdat, td.data)

    def do_stat(self) -> None:
        for td in self.tds:
            with open(td.path, "rb") as f:
                st = os.fstat(f.fileno())
                self.expect.eq(st.st_size, td.fsize())

    def do_unlink(self) -> None:
        for td in self.tds:
            self.expect.is_reg(td.path)
            os.unlink(td.path)


class TestBaseCtx:
    def __init__(self, name: str, cfg: TestConfig) -> None:
        self.name = name
        self.cfg = copy.copy(cfg)
        self.expect = expect.Expect(name)
        self.seed = 0

    @staticmethod
    def suspend(nsec: int) -> None:
        time.sleep(nsec)

    def make_basepath(self) -> str:
        return self.make_path(self.name)

    def make_path(self, *subs) -> str:
        return os.path.join(self.mntpoint(), *subs)

    def make_rands(self, cnt: int, rsz: int) -> list[bytes]:
        self._seed_random()
        ret = []
        for _ in range(0, cnt):
            ret.append(self.make_rand(rsz))
        return ret

    def make_rand(self, rsz: int) -> bytes:
        self._seed_random()
        return random.randbytes(rsz)

    def make_td(self, sub: str, name: str, sz: int) -> TestData:
        return TestData(self.make_path(sub, name), self.make_rand(sz))

    def make_tds(self, cnt: int, sub: str, sz: int) -> TestDataSet:
        tds = []
        for idx in range(0, cnt):
            tds.append(self.make_td(sub, str(idx), sz))
        return TestDataSet(self.expect, tds)

    def _seed_random(self):
        if self.seed == 0:
            self.seed = datetime.datetime.now().second
            random.seed(self.seed)

    def repodir(self) -> str:
        return self.cfg.repodir

    def mntpoint(self) -> str:
        return self.cfg.mntdir

    def _repodir_name(self, name: str = "") -> str:
        if not name:
            name = self.name
        return os.path.join(self.repodir(), name)


class TestCtx(TestBaseCtx):
    def __init__(self, name: str, cfg: TestConfig) -> None:
        TestBaseCtx.__init__(self, name, cfg)
        self.cmd = cmd.Cmds()
        self.password = "123456"

    def exec_init(self) -> None:
        self.cmd.silofs.init(self.cfg.repodir)

    def exec_mkfs(self, gsize: int = 2, name: str = ""):
        gibi = 2**30
        size = gsize * gibi
        self.cmd.silofs.mkfs(self._repodir_name(name), size)

    def exec_mount(
        self,
        name: str = "",
        allow_hostids: bool = False,
    ) -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.mount(repodir_name, self.cfg.mntdir, allow_hostids)

    def exec_umount(self) -> None:
        self.cmd.silofs.umount(self.mntpoint())

    def exec_setup_fs(self, gsize: int = 2) -> None:
        self.exec_init()
        self.exec_mkfs(gsize)
        self.exec_mount()

    def exec_snap(self, name: str) -> None:
        self.cmd.silofs.snap(name, self.mntpoint())

    def exec_rmfs(self, name: str = "") -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.rmfs(repodir_name)

    def exec_fsck(self, name: str = "") -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.fsck(repodir_name)

    def do_mkdirs(self, name: str) -> str:
        base = self.make_path(name)
        os.makedirs(base, exist_ok=False)
        return base

    def do_rmtree(self, name: str) -> None:
        base = self.make_path(name)
        shutil.rmtree(base)


class TestDef:
    def __init__(self, hook: typing.Callable[[TestCtx], None]) -> None:
        mod = "." + hook.__module__
        base = mod.split(".")[-1]
        self.hook = hook
        self.name = f"{base}.{hook.__name__}"
