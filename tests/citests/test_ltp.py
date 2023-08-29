# SPDX-License-Identifier: GPL-3.0
import copy
import os
import pathlib

from . import ctx
from . import utils


# pylint: disable=R0902,R0903
class LtpFsstressArgs:
    def __init__(self) -> None:
        self.count = 1
        self.procs = 1
        self.creat = 1
        self.fdatasync = 0
        self.fsync = 0
        self.getdents = 0
        self.link = 0
        self.mkdir = 0
        self.read = 0
        self.readlink = 0
        self.rename = 0
        self.rmdir = 0
        self.stat = 0
        self.symlink = 0
        self.sync = 0
        self.truncate = 0
        self.unlink = 0
        self.write = 0

    def make_cmd(self, fsstress: pathlib.Path, testdir: pathlib.Path) -> str:
        cmd = f"{fsstress} -r -d {testdir} "
        cmd = cmd + f"-n {self.count} -p {self.procs} "
        cmd = cmd + f"-f creat={self.creat} "
        cmd = cmd + f"-f fdatasync={self.fdatasync} "
        cmd = cmd + f"-f fsync={self.fsync} "
        cmd = cmd + f"-f getdents={self.getdents} "
        cmd = cmd + f"-f link={self.link} "
        cmd = cmd + f"-f mkdir={self.mkdir} "
        cmd = cmd + f"-f read={self.read} "
        cmd = cmd + f"-f readlink={self.readlink} "
        cmd = cmd + f"-f rename={self.rename} "
        cmd = cmd + f"-f rmdir={self.rmdir} "
        cmd = cmd + f"-f stat={self.stat} "
        cmd = cmd + f"-f symlink={self.symlink} "
        cmd = cmd + f"-f sync={self.sync} "
        cmd = cmd + f"-f truncate={self.truncate} "
        cmd = cmd + f"-f unlink={self.unlink} "
        cmd = cmd + f"-f write={self.write} "
        return cmd


class LtpConfig:
    def __init__(self, base: pathlib.Path) -> None:
        self.env = os.environ.copy()
        self.base = base
        self.srcdir = base / "ltp-src"
        self.tmpdir = base / "ltp-tmp"
        self.prefix = self.srcdir / "ltproot"
        self.ltproot = self.prefix
        self.ltp_dev_fs_type = "silofs"

    def mkenv(self) -> dict[str, str]:
        env: dict[str, str] = {}
        env["LTPROOT"] = str(self.ltproot)
        env["LTP_DEV_FS_TYPE"] = str(self.ltp_dev_fs_type)
        env["LTP_COLORIZE_OUTPUT"] = "0"
        env["TMPDIR"] = str(self.tmpdir)
        env["PATH"] = self._mkenv_path()
        return env

    def _mkenv_path(self) -> str:
        ltp_path = self.testcases_bin()
        cur_path = self.env.get("PATH", "")
        return ":".join([cur_path, str(ltp_path)]).strip(":")

    def makedirs(self) -> None:
        self.srcdir.mkdir(parents=True)
        self.tmpdir.mkdir(parents=True)

    def testcases_bin(self) -> pathlib.Path:
        return self.ltproot / "testcases" / "bin"


def test_ltp(tc: ctx.TestCtx) -> None:
    url = "https://github.com/linux-test-project/ltp"
    name = utils.selfname()
    tc.exec_setup_fs(64, writeback_cache=False)
    base = tc.create_fstree(name)
    config = LtpConfig(base)
    config.makedirs()
    ret = tc.cmd.git.clone(url, config.srcdir)
    if ret == 0:
        _install_ltp(tc, config)
        _runltp_base_tests(tc, config)
        _runltp_more_tests(tc, config)
        _runltp_fsstress(tc, config)
    tc.remove_fstree(name)
    tc.exec_umount()


def _install_ltp(tc: ctx.TestCtx, config: LtpConfig) -> None:
    tc.cmd.sh.run_ok("make autotools", config.srcdir)
    tc.cmd.sh.run_ok(
        f"./configure --disable-metadata --prefix={config.prefix}",
        config.srcdir,
    )
    tc.cmd.sh.run_ok("make", config.srcdir)
    tc.cmd.sh.run_ok("make install", config.srcdir)


def _runltp_base_tests(tc: ctx.TestCtx, config: LtpConfig) -> None:
    _runltp_tests_by(tc, config, copy.copy(_LTP_TESTS))


def _runltp_more_tests(tc: ctx.TestCtx, config: LtpConfig) -> None:
    _runltp_tests_by(tc, config, copy.copy(_LTP_TESTS_MORE))


def _runltp_tests_by(
    tc: ctx.TestCtx, config: LtpConfig, tests: list[str]
) -> None:
    for test in tests:
        test_path = config.testcases_bin() / test
        if test_path.is_file():
            tc.cmd.sh.run_ok(str(test_path), config.base, config.mkenv())


def _runltp_fsstress(tc: ctx.TestCtx, config: LtpConfig) -> None:
    args = LtpFsstressArgs()
    args.count = 1000
    args.procs = 10
    args.creat = 1000
    args.fdatasync = 1
    args.fsync = 1
    args.getdents = 10
    args.link = 10
    args.mkdir = 10
    args.read = 1000
    args.readlink = 10
    args.rename = 10
    args.rmdir = 10
    args.stat = 100
    args.symlink = 10
    args.sync = 1
    args.truncate = 10
    args.unlink = 10
    args.write = 1000
    _runltp_fsstress_with(tc, config, args)


def _runltp_fsstress_with(
    tc: ctx.TestCtx, config: LtpConfig, args: LtpFsstressArgs
) -> None:
    fsstress_path = config.testcases_bin() / "fsstress"
    if fsstress_path.is_file():
        cmd = args.make_cmd(fsstress_path, config.tmpdir)
        tc.cmd.sh.run_ok(cmd, config.base, config.mkenv())


_LTP_TESTS = [
    "aio01",
    "aio02",
    "chdir04",
    "chmod01",
    "close01",
    "close02",
    "copy_file_range03",
    "creat01",
    "creat03",
    "creat05",
    "creat07",
    "dio_append",
    "dio_sparse",
    "diotest1",
    "diotest2",
    "diotest3",
    "diotest4",
    "diotest5",
    "diotest6",
    "faccessat01",
    "fallocate01",
    "fallocate02",
    "fallocate03",
    "fchdir01",
    "fchdir02",
    "fchmod01",
    "fchmodat01",
    "fchown01",
    "fchownat01",
    "fdatasync01",
    "fdatasync02",
    "fgetxattr03",
    "flock01",
    "flock02",
    "flock03",
    "flock04",
    "flock06",
    "fstat02",
    "fstat03",
    "fstatat01",
    "fstatfs02",
    "fsync02",
    "fsync03",
    "ftest01",
    "ftest02",
    "ftest03",
    "ftest04",
    "ftest05",
    "ftest06",
    "ftest07",
    "ftest08",
    "ftruncate01",
    "ftruncate03",
    "futimesat01",
    "getdents01",
    "getdents02",
    "getdents02",
    "inode01",
    "inode02",
    "link02",
    "link03",
    "link05",
    "linkat01",
    "llseek01",
    "llseek02",
    "llseek03",
    "lseek01",
    "lseek02",
    "lseek07",
    "lstat01",
    "lstat02",
    "madvise03",
    "madvise05",
    "madvise10",
    "mkdirat01",
    "mknodat01",
    "mmap001",
    "mmap01",
    "mmap02",
    "mmap03",
    "mmap04",
    "mmap05",
    "mmap06",
    "mmap07",
    "mmap08",
    "mmap09",
    "mmap12",
    "mmap13",
    "mmap17",
    "mmap18",
    "mmap19",
    "mmap2",
    "mmap20",
    "mmap-corruption01",
    "mmapstress01",
    "mmapstress02",
    "mmapstress03",
    "mmapstress04",
    "mmapstress05",
    "mmapstress08",
    "msync01",
    "msync02",
    "msync03",
    "munmap01",
    "munmap02",
    "munmap03",
    "open01",
    "open03",
    "open04",
    "open06",
    "open07",
    "open09",
    "open13",
    "openat01",
    "openat02",
    "openat201",
    "openat202",
    "openat203",
    "pread01",
    "pread02",
    "preadv01",
    "preadv02",
    "preadv201",
    "preadv202",
    "pwrite01",
    "pwrite02",
    "pwrite03",
    "pwrite04",
    "pwritev01",
    "pwritev02",
    "pwritev201",
    "pwritev202",
    "read01",
    "read02",
    "read03",
    "read04",
    "readahead01",
    "readdir01",
    "readlinkat01",
    "readlinkat02",
    "readv01",
    "readv02",
    "removexattr01",
    "removexattr02",
    "rename14",
    "renameat201",
    "renameat202",
    "rmdir01",
    "stat02",
    "statfs02",
    "statvfs02",
    "statx02",
    "statx03",
    "symlink01",
    "symlink04",
    "symlink05",
    "symlinkat01",
    "truncate02",
    "unlink05",
    "unlink07",
    "unlinkat01",
    "write01",
    "write02",
    "write03",
    "write04",
    "write05",
    "write06",
    "writev01",
    "writev02",
    "writev05",
    "writev06",
    "writev07",
]

_LTP_TESTS_MORE = [
    "file01.sh",
    "growfiles",
    "lftest",
    "ln_tests.sh",
    "mv_tests.sh",
    "openfile",
]
