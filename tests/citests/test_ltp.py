# SPDX-License-Identifier: GPL-3.0
import copy
import os
import pathlib

from . import ctx
from . import utils


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
        _runltp_tests(tc, config)
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


def _runltp_tests(tc: ctx.TestCtx, config: LtpConfig):
    _runltp_base_tests(tc, config)
    _runltp_sh_tests(tc, config)


def _runltp_base_tests(tc: ctx.TestCtx, config: LtpConfig):
    tests = copy.copy(_LTP_TESTS)
    for test in tests:
        exe = config.testcases_bin() / test
        if _is_normal_test(exe):
            tc.cmd.sh.run_ok(str(exe), config.base, config.mkenv())


def _runltp_sh_tests(tc: ctx.TestCtx, config: LtpConfig):
    tests = copy.copy(_LTP_TESTS_SH)
    for test in tests:
        exe = config.testcases_bin() / test
        if _is_shell_test(exe):
            tc.cmd.sh.run_ok(str(exe), config.base, config.mkenv())


def _is_shell_test(test_path: pathlib.Path) -> bool:
    return test_path.is_file() and test_path.suffix == ".sh"


def _is_normal_test(test_path: pathlib.Path) -> bool:
    return test_path.is_file() and test_path.suffix == ""


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
    "ftruncate01",
    "ftruncate03",
    "getdents01",
    "getdents02",
    "link02",
    "link03",
    "link05",
    "link08",
    "linkat01",
    "llseek01",
    "llseek02",
    "llseek03",
    "lseek01",
    "lseek02",
    "lseek07",
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
    "preadv01",
    "read01",
    "rmdir01",
    "symlink01",
    "symlink04",
    "symlink05",
    "symlinkat01",
    "truncate02",
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

_LTP_TESTS_SH = [
    "file01.sh",
    "ln_tests.sh",
    "mv_tests.sh",
]

_LTP_TESTS_MORE = [
    "aiodio_append",
    "aiodio_sparse",
    "close_range02",
    "dio_append",
    "dio_sparse",
    "diotest1",
    "diotest2",
    "diotest3",
    "diotest4",
    "diotest5",
    "diotest6",
    "dio_truncate",
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
    "growfiles",
    "inode01",
    "inode02",
    "lftest",
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
    "mmap20",
    "mmap2",
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
    "name_to_handle_at02",
    "openfile",
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
]
