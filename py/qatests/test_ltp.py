# SPDX-License-Identifier: GPL-3.0
import copy
import os
from pathlib import Path

from .ctx import TestEnv


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

    def make_cmdline(self, fsstress: Path, testdir: Path) -> str:
        cmdline = f"{fsstress} -r -d {testdir} "
        cmdline = cmdline + f"-n {self.count} -p {self.procs} "
        cmdline = cmdline + f"-f creat={self.creat} "
        cmdline = cmdline + f"-f fdatasync={self.fdatasync} "
        cmdline = cmdline + f"-f fsync={self.fsync} "
        cmdline = cmdline + f"-f getdents={self.getdents} "
        cmdline = cmdline + f"-f link={self.link} "
        cmdline = cmdline + f"-f mkdir={self.mkdir} "
        cmdline = cmdline + f"-f read={self.read} "
        cmdline = cmdline + f"-f readlink={self.readlink} "
        cmdline = cmdline + f"-f rename={self.rename} "
        cmdline = cmdline + f"-f rmdir={self.rmdir} "
        cmdline = cmdline + f"-f stat={self.stat} "
        cmdline = cmdline + f"-f symlink={self.symlink} "
        cmdline = cmdline + f"-f sync={self.sync} "
        cmdline = cmdline + f"-f truncate={self.truncate} "
        cmdline = cmdline + f"-f unlink={self.unlink} "
        cmdline = cmdline + f"-f write={self.write} "
        return cmdline


class LtpConfig:
    def __init__(self, base: Path) -> None:
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

    def testcases_bin(self) -> Path:
        return self.ltproot / "testcases" / "bin"


def test_ltp(env: TestEnv) -> None:
    url = "https://github.com/linux-test-project/ltp"
    name = env.uniq_name()
    env.exec_setup_fs(64, writeback_cache=False)
    base = env.create_fstree(name)
    config = LtpConfig(base)
    config.makedirs()
    ret = env.subcmd.git.clone(url, config.srcdir)
    if ret == 0:
        _install_ltp(env, config)
        _runltp_base_tests(env, config)
        _runltp_more_tests(env, config)
        _runltp_fsstress(env, config)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _install_ltp(env: TestEnv, config: LtpConfig) -> None:
    env.subcmd.sh.run_ok("make autotools", config.srcdir)
    env.subcmd.sh.run_ok(
        f"./configure --disable-metadata --prefix={config.prefix}",
        config.srcdir,
    )
    env.subcmd.sh.run_ok("make", config.srcdir)
    env.subcmd.sh.run_ok("make install", config.srcdir)


def _runltp_base_tests(env: TestEnv, config: LtpConfig) -> None:
    _runltp_tests_by(env, config, copy.copy(_LTP_TESTS))


def _runltp_more_tests(env: TestEnv, config: LtpConfig) -> None:
    _runltp_tests_by(env, config, copy.copy(_LTP_TESTS_MORE))


def _runltp_tests_by(
    env: TestEnv, config: LtpConfig, tests: list[str]
) -> None:
    for test in tests:
        test_path = config.testcases_bin() / test
        if test_path.is_file():
            env.subcmd.sh.run_ok(str(test_path), config.base, config.mkenv())


def _runltp_fsstress(env: TestEnv, config: LtpConfig) -> None:
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
    _runltp_fsstress_with(env, config, args)


def _runltp_fsstress_with(
    env: TestEnv, config: LtpConfig, args: LtpFsstressArgs
) -> None:
    fsstress_path = config.testcases_bin() / "fsstress"
    if fsstress_path.is_file():
        subcmd = args.make_cmdline(fsstress_path, config.tmpdir)
        env.subcmd.sh.run_ok(subcmd, config.base, config.mkenv())


_LTP_TESTS = [
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
    "getdents01",
]
