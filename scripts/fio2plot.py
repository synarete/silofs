#!/usr/bin/env python3
"""
Run fio on various file-systems and digest its output into visual plots.
"""

import sys
import os
import os.path
import time
import stat
import math
import shutil
import itertools
import subprocess
import scipy.constants as consts
import matplotlib as mpl
import matplotlib.pyplot as plt

__author__ = "Shachar Sharon"
__license__ = "GPL-3.0"
__copyright__ = "Copyright (C) 2022 Shachar Sharon"


class FioArgs:
    """
    FioArgs represents a subset of fio's input arguments
    """

    def __init__(self, wdir: str, numjobs: int) -> None:
        self.fio_bin = locate_fio()
        self.wdir = os.path.abspath(wdir)
        self.numjobs = numjobs
        self.bs = 64
        self.bs_size = self.bs * consts.kibi
        self.rwmixwrite = 70
        self.readwrite = "rw"
        self.ioengine = "psync"
        self.fallocate = "keep"
        self.size = consts.gibi
        self.runtime = 30
        self.base = os.path.basename(self.wdir)
        self.name = self.make_name()

    def make_name(self) -> str:
        fs_type = fstype_of(self.wdir)
        return "{fs_type}-j{jobs}".format(fs_type=fs_type, jobs=self.numjobs)

    def to_argv(self) -> list[str]:
        args = [self.fio_bin]
        args += ["--name={}".format(self.name)]
        args += ["--directory={}".format(self.wdir)]
        args += ["--numjobs={}".format(self.numjobs)]
        args += ["--bs={}".format(self.bs_size)]
        args += ["--size={}".format(self.size)]
        args += ["--fallocate={}".format(self.fallocate)]
        args += ["--readwrite={}".format(self.readwrite)]
        args += ["--rwmixwrite={}".format(self.rwmixwrite)]
        args += ["--ioengine={}".format(self.ioengine)]
        args += ["--time_based"] + ["--runtime={}".format(self.runtime)]
        args += ["--sync=0", "--direct=0", "--thinktime=0"]
        args += ["--thinktime=0", "--norandommap", "--group_reporting"]
        args += ["--randrepeat=1", "--unlink=1", "--fsync_on_close=1"]
        args += ["--minimal"]
        return args


class FioData:
    """
    FioData represents a subset of fio's minimal output data.

    For reference of fio output fields, see:
      https://fio.readthedocs.io/en/latest/fio_doc.html
      https://www.andypeace.com/fio_minimal.html
    """

    def __init__(self, fio_minimal) -> None:
        """Converts raw fio minimal output into python object repr"""
        kibi = consts.kibi
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

    def to_text(self) -> str:
        ret = self.job_name + " "
        ret = ret + "rd_io_total={} ".format(self.rd_total_io)
        ret = ret + "rd_bw_kb={} ".format(self.rd_bw_kb)
        ret = ret + "rd_iops={} ".format(self.rd_iops)
        ret = ret + "rd_lat_mean={} ".format(self.rd_lat_mean)
        ret = ret + "wr_total_io={} ".format(self.wr_total_io)
        ret = ret + "wr_bw_kb={} ".format(self.wr_bw_kb)
        ret = ret + "wr_iops={} ".format(self.wr_iops)
        ret = ret + "wr_lat_mean={} ".format(self.wr_lat_mean)
        return ret


class FioInfo:
    """A pair of fio's input arguments and output data"""

    def __init__(self, args: FioArgs, data: FioData):
        self.args = args
        self.data = data


def locate_fio() -> str:
    """Finds location of fio executable binary on local host"""
    loc = shutil.which("fio")
    if loc is None:
        raise RuntimeError("unable to locate fio")
    return loc


def fstype_of(wdir: str) -> str:
    """Resolve file-system type of a given work-directory"""
    lines = []
    with open("/proc/mounts") as fmounts:
        lines = fmounts.readlines()
    st = os.stat(wdir)
    for line in lines:
        fields = line.split()
        mntp = fields[1]
        fs_type = fields[2]
        try:
            mntp_st = os.stat(mntp)
            if mntp_st.st_dev == st.st_dev:
                return fs_type
        except Exception:
            continue
    return "unknownfs"


def run_fio_once(args: FioArgs) -> FioData:
    """
    Execute fio with explicit arguments and return output as python object
    representation
    """
    res = subprocess.run(
        args.to_argv(),
        check=True,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    err = str(res.stderr).strip()
    if len(err) > 0:
        raise RuntimeError("fio error: " + err)
    return FioData(res.stdout)


def run_fios(wdirs: list[str]) -> dict[str, list[FioInfo]]:
    """
    For-each input work-dir execute fio with different jobs-count and
    return the outputs as collection of python objects.
    """
    fio_info_dict = {}
    for wdir in wdirs:
        fio_info_list = []
        for jobs in (1, 2, 4, 8):
            args = FioArgs(wdir, jobs)
            print("# " + " ".join(args.to_argv()))
            data = run_fio_once(args)
            print(data.to_text())
            fio_info_list.append(FioInfo(args, data))
            time.sleep(1)
        fio_info_dict[wdir] = fio_info_list
    return fio_info_dict


def align_up(val: int, align: int) -> int:
    """Align-up value"""
    return math.floor((val + align + 1) / align) * align


def calc_max_write_bw(fio_info_dict: dict[str, list[FioInfo]]) -> int:
    """Calculate maximal bandwidth value and aligned-up"""
    bw_mb_max = 0
    for wdir in fio_info_dict:
        fio_info_list = fio_info_dict[wdir]
        for fio_info in fio_info_list:
            fio_data = fio_info.data
            bw_mb_max = max(bw_mb_max, fio_data.wr_bw_mb)
    return align_up(bw_mb_max, 10)


def color_labels_of():
    """Returns plot-bars colors"""
    cols = [
        "tab:blue",
        "tab:red",
        "tab:green",
        "tab:orange",
        "tab:purple",
        "tab:cyan",
    ]
    return itertools.cycle(cols)


def title_of(fio_info_dict: dict[str, list[FioInfo]]) -> str:
    """Returns appropriate title for a given fio data-set"""
    title = "Read/Write"
    fio_info = None
    for wdir in fio_info_dict:
        fio_info_list = fio_info_dict[wdir]
        if len(fio_info_list) > 0:
            fio_info = fio_info_list[0]
        break
    if fio_info is None:
        return title
    fio_args = fio_info.args
    if fio_args.readwrite == "randrw":
        title = "Random mixed reads and writes"
    elif fio_args.readwrite == "rw":
        title = "Sequential mixed reads and writes"
    bs = fio_args.bs
    wr = fio_args.rwmixwrite
    rd = 100 - wr
    extra = "(bs={bs}K rd={rd}% wr={wr}%)".format(bs=bs, rd=rd, wr=wr)
    return title + " " + extra


def plot_fio_bw(fio_info_dict: dict[str, list[FioInfo]]) -> None:
    """
    Plot series of fio output data as I/O performance graph.
    """
    mpl.style.use("bmh")
    fig, ax = plt.subplots()
    fig.set_facecolor("ghostwhite")
    fig.suptitle("Silofs I/O Performance vs Local FS", fontsize="xx-large")
    ax.set_title(title_of(fio_info_dict), fontsize="x-large", pad=15)
    ax.set_xlabel("File-system/Jobs", fontsize="large", labelpad=15)
    ax.set_ylabel("Write bandwidth (MB/s)", fontsize="large", labelpad=15)
    ax.set(ylim=(0, calc_max_write_bw(fio_info_dict)))
    ax.grid(True)
    # ax.legend()
    cols = color_labels_of()
    for wdir in fio_info_dict:
        fio_info_list = fio_info_dict[wdir]
        col = next(cols)
        for fio_info in fio_info_list:
            fio_data = fio_info.data
            wr_bw_mb = fio_data.wr_bw_mb
            tag = fio_data.job_name
            ax.bar(tag, wr_bw_mb, width=0.5, color=col, edgecolor="gray")
    plt.show()


def argv_wdirs() -> list[str]:
    """Program's input list of working-directories, or current work if none"""
    wdirs = []
    for wdir in sys.argv[1:]:
        wdir_st = os.stat(wdir)
        if stat.S_ISDIR(wdir_st.st_mode):
            wdirs.append(wdir)
    if len(wdirs) == 0:
        wdirs = [os.getcwd()]
    return wdirs


def main():
    """Program's main"""
    locate_fio()
    plot_fio_bw(run_fios(argv_wdirs()))


if __name__ == "__main__":
    main()
