# SPDX-License-Identifier: GPL-3.0
import copy
import os
import time
import typing
from concurrent import futures
from pathlib import Path

from . import conf
from . import expect
from . import subcmd
from . import utils


class TestData:
    def __init__(self, path: Path, sz: int) -> None:
        self.path = path
        self.base = 0
        self.size = sz
        self.data = utils.prandbytes(sz)

    def fsize(self) -> int:
        return self.base + self.size

    def do_write(self) -> None:
        self.path.write_bytes(self.data)

    def do_read(self) -> bytes:
        return self.path.read_bytes()

    def do_stat(self) -> os.stat_result:
        return self.path.stat()

    def do_unlink(self) -> None:
        self.path.unlink()


class TestDataSet:
    def __init__(self, exp: expect.Expect, tds: list[TestData]) -> None:
        self.expect = exp
        self.tds = tds

    def do_makedirs(self) -> list[Path]:
        ret = set[Path]()
        for td in self.tds:
            dpath = td.path.parent
            dpath.mkdir(parents=True, exist_ok=True)
            self.expect.is_dir(dpath)
            ret.add(dpath)
        return list(ret)

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
            st = td.do_stat()
            self.expect.eq(st.st_size, td.fsize())

    def do_read(self) -> None:
        for td in self.tds:
            rdat = td.do_read()
            self.expect.eq(rdat, td.data)

    def do_stat(self) -> None:
        for td in self.tds:
            st = td.do_stat()
            self.expect.eq(st.st_size, td.fsize())

    def do_unlink(self) -> None:
        for td in self.tds:
            self.expect.is_reg(td.path)
            td.do_unlink()

    def pathnames(self) -> list[Path]:
        ret = set[Path]()
        for td in self.tds:
            ret.add(td.path)
        return list(ret)


# pylint: disable=R0904,R0902
class TestEnv:
    def __init__(self, name: str, cfg: conf.Config) -> None:
        self.name = name
        self.uniq = 0
        self.cfg = copy.copy(cfg)
        self.expect = expect.Expect(name)
        self.executor = futures.ThreadPoolExecutor()
        self.subcmd = subcmd.Subcmds(
            cfg.params.use_stdalloc, cfg.params.allow_coredump
        )
        self.fsids = conf.FsIdsConf()

    @staticmethod
    def suspend(nsec: int) -> None:
        time.sleep(nsec)

    @staticmethod
    def make_rands(n: int) -> bytes:
        return utils.prandbytes(n)

    def uniq_name(self) -> str:
        self.uniq = self.uniq + 1
        return f"{self.name}_{self.uniq}"

    def make_basepath(self) -> Path:
        return self.make_path(self.name)

    def make_path(self, *subs) -> Path:
        return Path(self.mntpoint(), *subs)

    def make_td(self, sub: str, name: str, sz: int) -> TestData:
        path = self.make_path(sub, name)
        return TestData(path, sz)

    def make_tds(self, cnt: int, sub: str, sz: int) -> TestDataSet:
        tds = []
        for idx in range(0, cnt):
            tds.append(self.make_td(sub, str(idx), sz))
        return TestDataSet(self.expect, tds)

    def create_data(self, cnt: int, sub: str, sz: int) -> TestDataSet:
        tds = self.make_tds(cnt, sub, sz)
        tds.do_makedirs()
        tds.do_write()
        tds.do_read()
        return tds

    def create_fstree(self, name: str) -> Path:
        path = self.make_path(name)
        self._create_fstree_at(path)
        return path

    def _create_fstree_at(self, path: Path) -> None:
        self.expect.not_exists(path)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)

    def remove_fstree(self, name: str) -> None:
        path = self.make_path(name)
        self._remove_fstree_at(path)

    def _remove_fstree_at(self, path: Path) -> None:
        self.expect.exists(path)
        self.expect.is_dir(path)
        utils.rmtree_at(path)

    def repodir(self) -> Path:
        return self.cfg.basedir / "repo"

    def mntpoint(self) -> Path:
        return self.cfg.mntdir

    def _repodir_name(self, name: str = "") -> Path:
        if not name:
            name = self.name
        return self.repodir() / name

    def _passwd(self) -> str:
        return self.cfg.params.password

    def exec_init(
        self, sup_groups: bool = False, allow_root: bool = False
    ) -> None:
        self.subcmd.silofs.init(self.repodir(), sup_groups, allow_root)
        self._update_fsids()

    def exec_mkfs(
        self,
        gsize: int = 2,
        name: str = "",
    ):
        gibi = 2**30
        self.subcmd.silofs.mkfs(
            repodir_name=self._repodir_name(name),
            size=gsize * gibi,
            password=self._passwd(),
        )
        self._require_bref(name)

    # pylint: disable=R0917
    def exec_mount(
        self,
        name: str = "",
        allow_hostids: bool = False,
        allow_xattr_acl: bool = False,
        writeback_cache: bool = True,
        buffer_copy_mode: bool = False,
    ) -> None:
        self._require_bref(name)
        repodir_name = self._repodir_name(name)
        self.subcmd.silofs.mount(
            repodir_name=repodir_name,
            mntpoint=self.cfg.mntdir,
            password=self._passwd(),
            allow_hostids=allow_hostids,
            allow_xattr_acl=allow_xattr_acl,
            writeback_cache=writeback_cache,
            buffer_copy_mode=buffer_copy_mode,
        )

    def exec_umount(self) -> None:
        self.subcmd.silofs.umount(self.mntpoint())

    def exec_setup_fs(
        self,
        gsize: int = 2,
        allow_xattr_acl: bool = False,
        writeback_cache: bool = True,
    ) -> None:
        self.exec_init()
        self.exec_mkfs(gsize)
        self.exec_mount(
            allow_xattr_acl=allow_xattr_acl, writeback_cache=writeback_cache
        )
        self.exec_lsmnt()

    def exec_teardown_fs(self) -> None:
        self.exec_lsmnt()
        self.exec_umount()
        self.exec_rmfs()

    def exec_snap(self, name: str) -> None:
        self.subcmd.silofs.snap(name, self.mntpoint(), self._passwd())
        self._require_bref(name)

    def exec_snap_offline(self, mainname: str, snapname: str) -> None:
        self.subcmd.silofs.snap_offline(
            snapname, self._repodir_name(mainname), self._passwd()
        )
        self._require_bref(snapname)

    def exec_tune(self, path: Path, ftype: int = 2) -> None:
        self.subcmd.silofs.tune(path, ftype)

    def exec_tune2(self, path_list: list[Path]) -> None:
        for path in path_list:
            self.subcmd.silofs.tune(path, 2)

    def exec_rmfs(self, name: str = "") -> None:
        self._require_bref(name)
        repodir_name = self._repodir_name(name)
        self.subcmd.silofs.rmfs(repodir_name, self._passwd())

    def exec_fsck(self, name: str = "") -> None:
        self._require_bref(name)
        repodir_name = self._repodir_name(name)
        self.subcmd.silofs.fsck(repodir_name, self._passwd())

    def exec_view(self, name: str = "") -> list[str]:
        self._require_bref(name)
        repodir_name = self._repodir_name(name)
        return list(self.subcmd.silofs.view(repodir_name, self._passwd()))

    def exec_archive(self, arname: str, name: str = "") -> None:
        self._require_bref(name)
        repodir_name = self._repodir_name(name)
        self.subcmd.silofs.archive(repodir_name, arname, self._passwd())

    def exec_restore(self, arname: str, name: str = "") -> None:
        repodir_name = self._repodir_name(name)
        self.subcmd.silofs.restore(repodir_name, arname, self._passwd())

    def exec_lsmnt(self) -> None:
        mntp = self.cfg.mntdir
        mnts = self.subcmd.silofs.lsmnt()
        self.expect.within(mntp, mnts)

    def _update_fsids(self) -> None:
        self.fsids = conf.load_fsids(self.repodir())

    def _require_bref(self, name: str = "") -> None:
        conf.load_bref(self._repodir_name(name))


# pylint: disable=R0903
class TestDef:
    def __init__(self, hook: typing.Callable[[TestEnv], None]) -> None:
        mod = "." + hook.__module__
        base = mod.split(".")[-1]
        self.hook = hook
        self.name = f"{base}.{hook.__name__}"
