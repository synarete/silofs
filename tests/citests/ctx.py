# SPDX-License-Identifier: GPL-3.0
import copy
import datetime
import os
import random
import shutil
import time
import typing
from concurrent import futures

from . import cmd
from . import expect


# pylint: disable=R0903
class TestConfig:
    def __init__(self, basedir: str, mntdir: str) -> None:
        self.basedir = os.path.realpath(basedir)
        self.mntdir = os.path.realpath(mntdir)
        self.repodir = os.path.join(self.basedir, "repo")
        self.password = "0123456789abcdef"


class TestData:
    def __init__(self, path: str, data: bytes) -> None:
        self.path = path
        self.data = data
        self.base = 0

    def fsize(self) -> int:
        return self.base + len(self.data)

    def do_write(self) -> None:
        with open(self.path, "wb") as f:
            f.write(self.data)

    def do_read(self) -> bytes:
        with open(self.path, "rb") as f:
            return f.read(len(self.data))

    def prune_data(self) -> None:
        self.data = bytes(0)


class TestDataSet:
    def __init__(self, exp: expect.Expect, tds: list[TestData]) -> None:
        self.expect = exp
        self.tds = tds

    def do_makedirs(self) -> None:
        for td in self.tds:
            dpath = os.path.dirname(td.path)
            os.makedirs(dpath, exist_ok=True)
            self.expect.is_dir(dpath)

    def do_rmdirs(self) -> None:
        dds = {}
        for td in self.tds:
            dpath = os.path.dirname(td.path)
            if dpath not in dds:
                self.expect.is_dir(dpath)
                os.rmdir(dpath)
                dds[dpath] = True

    def do_write(self) -> None:
        for td in self.tds:
            td.do_write()
            self.expect.is_reg(td.path)

    def do_read(self) -> None:
        for td in self.tds:
            rdat = td.do_read()
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

    def prune_data(self) -> None:
        for td in self.tds:
            td.prune_data()


class TestBaseCtx:
    def __init__(self, name: str, cfg: TestConfig) -> None:
        self.name = name
        self.cfg = copy.copy(cfg)
        self.expect = expect.Expect(name)
        self.executor = futures.ThreadPoolExecutor()
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

    def make_bytes(self, bsz: int, val: str = "") -> bytes:
        if not val:
            ret = bytes(bsz)
        else:
            ret = bytes(bsz * val[0], "utf-8")
        return ret

    def make_td(self, sub: str, name: str, sz: int, val: str = "") -> TestData:
        if val:
            dat = self.make_bytes(sz, val)
        else:
            dat = self.make_rand(sz)
        return TestData(self.make_path(sub, name), dat)

    def make_tds(
        self, cnt: int, sub: str, sz: int, val: str = ""
    ) -> TestDataSet:
        tds = []
        for idx in range(0, cnt):
            tds.append(self.make_td(sub, str(idx), sz, val))
        return TestDataSet(self.expect, tds)

    def create_data(
        self, cnt: int, sub: str, sz: int, val: str = ""
    ) -> TestDataSet:
        tds = self.make_tds(cnt, sub, sz, val)
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        return tds

    def do_mkdirs(self, name: str) -> str:
        base = self.make_path(name)
        os.makedirs(base, exist_ok=False)
        return base

    def do_rmtree(self, name: str) -> None:
        base = self.make_path(name)
        shutil.rmtree(base)

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

    def _passwd(self) -> str:
        return self.cfg.password


class TestCtx(TestBaseCtx):
    def __init__(self, name: str, cfg: TestConfig) -> None:
        TestBaseCtx.__init__(self, name, cfg)
        self.cmd = cmd.Cmds()

    def exec_init(self) -> None:
        self.cmd.silofs.init(self.cfg.repodir)

    def exec_mkfs(self, gsize: int = 2, name: str = ""):
        gibi = 2**30
        size = gsize * gibi
        self.cmd.silofs.mkfs(self._repodir_name(name), size, self._passwd())

    def exec_mount(
        self,
        name: str = "",
        allow_hostids: bool = False,
    ) -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.mount(
            repodir_name, self.cfg.mntdir, self._passwd(), allow_hostids
        )

    def exec_umount(self) -> None:
        self.cmd.silofs.umount(self.mntpoint())

    def exec_setup_fs(self, gsize: int = 2) -> None:
        self.exec_init()
        self.exec_mkfs(gsize)
        self.exec_mount()

    def exec_snap(self, name: str) -> None:
        self.cmd.silofs.snap(name, self.mntpoint())

    def exec_snap_offline(self, mainname: str, snapname: str) -> None:
        self.cmd.silofs.snap_offline(
            snapname, self._repodir_name(mainname), self._passwd()
        )

    def exec_rmfs(self, name: str = "") -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.rmfs(repodir_name, self._passwd())

    def exec_fsck(self, name: str = "") -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.fsck(repodir_name, self._passwd())


class TestDef:
    def __init__(self, hook: typing.Callable[[TestCtx], None]) -> None:
        mod = "." + hook.__module__
        base = mod.split(".")[-1]
        self.hook = hook
        self.name = f"{base}.{hook.__name__}"
