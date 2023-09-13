# SPDX-License-Identifier: GPL-3.0

import pathlib

from . import cmd
from . import log
from . import utils
from .ctx import TestEnv


# pylint: disable=R0902,R0903
class FioInput:
    """
    FioInput represents a subset of fio's input arguments as python object
    """

    def __init__(
        self, wdir: pathlib.Path, njobs: int = 1, rwmix: int = 70
    ) -> None:
        self.wdir = str(wdir.resolve(strict=True))
        self.fs_type = utils.fstype_of(wdir)
        self.name = f"{self.fs_type}-j{njobs}".replace(".", "-")
        self.njobs = njobs
        self.bs = 64
        self.bs_size = self.bs * (2**10)
        self.rwmixwrite = rwmix
        self.readwrite = "rw"
        self.ioengine = "psync"
        self.fallocate = "keep"
        self.size = (2**31) // njobs
        self.runtime = 30
        self.verify = "xxhash"

    def to_argv(self) -> list[str]:
        args = ["--minimal"]
        args += [f"--name={self.name}"]
        args += [f"--directory={self.wdir}"]
        args += [f"--numjobs={self.njobs}"]
        args += [f"--bs={self.bs_size}"]
        args += [f"--size={self.size}"]
        args += [f"--fallocate={self.fallocate}"]
        args += [f"--readwrite={self.readwrite}"]
        args += [f"--rwmixwrite={self.rwmixwrite}"]
        args += [f"--ioengine={self.ioengine}"]
        args += [f"--runtime={self.runtime}"]
        args += [f"--verify={self.verify}"]
        args += ["--time_based", "--sync=0", "--direct=0", "--thinktime=0"]
        args += ["--norandommap", "--group_reporting", "--randrepeat=1"]
        args += ["--unlink=1", "--fsync_on_close=1"]
        return args


# pylint: disable=R0902,R0903
class FioOutput:
    """
    FioOutput represents a subset of fio's minimal output data.

    For reference of fio output fields, see:
      https://fio.readthedocs.io/en/latest/fio_doc.html
      https://www.andypeace.com/fio_minimal.html
    """

    def __init__(self, fio_minimal: str) -> None:
        """Converts raw fio minimal output into python object repr"""
        kibi = 2**10
        fields = ["0"] + fio_minimal.split(";")
        self.job_name = str(fields[3])
        self.rd_total_io = int(fields[6])
        self.rd_bw_kb = int(fields[7])
        self.rd_bw_mb = self.rd_bw_kb / kibi
        self.rd_iops = int(fields[8])
        self.rd_lat_mean = float(fields[40])
        self.wr_total_io = int(fields[47])
        self.wr_bw_kb = int(fields[48])
        self.wr_bw_mb = self.wr_bw_kb / kibi
        self.wr_iops = int(fields[49])
        self.wr_lat_mean = float(fields[81])


class FioExec(cmd.CmdExec):
    def __init__(self, base: pathlib.Path):
        cmd.CmdExec.__init__(self, "fio")
        self.base = base
        self.timeout = 180

    def execute_with(self, fio_in: FioInput) -> FioOutput:
        argv = fio_in.to_argv()
        wdir = str(self.base)
        fio_res = self.execute_sub(argv, wdir=wdir, timeout=self.timeout)
        fio_out = FioOutput(fio_res)
        return fio_out


def test_fio_simple(env: TestEnv) -> None:
    name = env.uniq_name()
    env.exec_setup_fs(8)
    base = env.create_fstree(name)
    fio_exe = FioExec(base)
    fio_in = FioInput(fio_exe.base)
    _print_fio_in(fio_in)
    fio_out = fio_exe.execute_with(fio_in)
    _print_fio_out(fio_out)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def test_fio_njobs(env: TestEnv) -> None:
    name = env.uniq_name()
    env.exec_setup_fs(64)
    base = env.create_fstree(name)
    fio_exe = FioExec(base)
    fio_in = FioInput(fio_exe.base, njobs=8, rwmix=50)
    _print_fio_in(fio_in)
    fio_out = fio_exe.execute_with(fio_in)
    _print_fio_out(fio_out)
    env.remove_fstree(name)
    env.exec_teardown_fs()


def _print_fio_in(fio_in: FioInput) -> None:
    fio_in_repr = utils.pformat(fio_in)
    log.printsl(f"FIO-IN: {fio_in_repr}")


def _print_fio_out(fio_out: FioOutput) -> None:
    fio_out_repr = utils.pformat(fio_out)
    log.printsl(f"FIO-OUT: {fio_out_repr}")
