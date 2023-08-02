# SPDX-License-Identifier: GPL-3.0
import copy
import pathlib
import random
import shutil
import time
import typing
from concurrent import futures

from . import cmd
from . import expect


# pylint: disable=R0903
class TestConfig:
    def __init__(self, basedir: pathlib.Path, mntdir: pathlib.Path) -> None:
        self.basedir = basedir.resolve(strict=True)
        self.mntdir = mntdir.resolve(strict=True)
        self.repodir = self.basedir / "repo"
        self.password = "0123456789abcdef"


class TestData:
    def __init__(self, path: pathlib.Path, data: bytes) -> None:
        self.path = path
        self.data = data
        self.base = 0

    def fsize(self) -> int:
        return self.base + len(self.data)

    def do_write(self) -> None:
        self.path.write_bytes(self.data)

    def do_read(self) -> bytes:
        return self.path.read_bytes()

    def prune_data(self) -> None:
        self.data = bytes(0)


class TestDataSet:
    def __init__(self, exp: expect.Expect, tds: list[TestData]) -> None:
        self.expect = exp
        self.tds = tds

    def do_makedirs(self) -> None:
        for td in self.tds:
            dpath = td.path.parent
            dpath.mkdir(parents=True, exist_ok=True)
            self.expect.is_dir(dpath)

    def do_rmdirs(self) -> None:
        dds = {}
        for td in self.tds:
            dpath = td.path.parent
            if dpath not in dds:
                self.expect.is_dir(dpath)
                dpath.rmdir()
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
            st = td.path.stat()
            self.expect.eq(st.st_size, td.fsize())

    def do_unlink(self) -> None:
        for td in self.tds:
            self.expect.is_reg(td.path)
            td.path.unlink()

    def prune_data(self) -> None:
        for td in self.tds:
            td.prune_data()


class TestBaseCtx:
    def __init__(self, name: str, cfg: TestConfig) -> None:
        self.name = name
        self.cfg = copy.copy(cfg)
        self.expect = expect.Expect(name)
        self.executor = futures.ThreadPoolExecutor()

    @staticmethod
    def suspend(nsec: int) -> None:
        time.sleep(nsec)

    def make_basepath(self) -> pathlib.Path:
        return self.make_path(self.name)

    def make_path(self, *subs) -> pathlib.Path:
        return pathlib.Path(self.mntpoint(), *subs)

    @staticmethod
    def make_rand(rsz: int) -> bytes:
        return random.randbytes(rsz)

    @staticmethod
    def make_bytes(bsz: int, val: str = "") -> bytes:
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

    def do_mkdirs(self, name: str) -> pathlib.Path:
        base = self.make_path(name)
        base.mkdir(parents=True, exist_ok=False)
        return base

    def do_rmtree(self, name: str) -> None:
        base = self.make_path(name)
        shutil.rmtree(base)

    def repodir(self) -> pathlib.Path:
        return self.cfg.repodir

    def mntpoint(self) -> pathlib.Path:
        return self.cfg.mntdir

    def _repodir_name(self, name: str = "") -> pathlib.Path:
        if not name:
            name = self.name
        return self.repodir() / name

    def _passwd(self) -> str:
        return self.cfg.password


class TestCtx(TestBaseCtx):
    def __init__(self, name: str, cfg: TestConfig) -> None:
        TestBaseCtx.__init__(self, name, cfg)
        self.cmd = cmd.Cmds()

    def exec_init(self) -> None:
        self.cmd.silofs.init(self.cfg.repodir)

    def exec_mkfs(
        self,
        gsize: int = 2,
        name: str = "",
        sup_groups: bool = False,
        allow_root: bool = False,
    ):
        gibi = 2**30
        size = gsize * gibi
        self.cmd.silofs.mkfs(
            self._repodir_name(name),
            size,
            self._passwd(),
            sup_groups,
            allow_root,
        )

    def exec_mount(
        self,
        name: str = "",
        allow_hostids: bool = False,
        writeback_cache: bool = True,
    ) -> None:
        repodir_name = self._repodir_name(name)
        self.cmd.silofs.mount(
            repodir_name,
            self.cfg.mntdir,
            self._passwd(),
            allow_hostids,
            writeback_cache,
        )

    def exec_umount(self) -> None:
        self.cmd.silofs.umount(self.mntpoint())

    def exec_setup_fs(
        self, gsize: int = 2, writeback_cache: bool = True
    ) -> None:
        self.exec_init()
        self.exec_mkfs(gsize)
        self.exec_mount(writeback_cache=writeback_cache)

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
