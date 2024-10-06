#!/usr/bin/env python3
"""
Converts fio output JSON files into performance plot.
"""

import json
import sys
import itertools
from pathlib import Path
from typing import Dict, List, Iterable

import matplotlib as mpl  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np

__author__ = "Shachar Sharon"
__license__ = "GPL-3.0"
__copyright__ = "Copyright (C) 2024 Shachar Sharon"


# pylint: disable=R0903
class ColorLabels:
    """
    Set of color-labels to plot bars, iterated
    """

    def __init__(self):
        color_labels = [
            "tab:red",
            "tab:blue",
            "tab:purple",
            "tab:green",
            "tab:orange",
            "tab:cyan",
        ]
        self.cols = itertools.cycle(color_labels)
        self.name_to_color: Dict[str, str] = {}

    def color_of(self, name: str) -> str:
        color = self.name_to_color.get(name, "")
        if not color:
            color = next(self.cols)
            self.name_to_color[name] = color
        return color


# pylint: disable=R0902,R0903
class FioData:
    """
    FioData represents a subset of fio's JSON-format output for a single job.
    """

    def __init__(self, json_data) -> None:
        """Converts fio JSON output into python object repr"""
        jobs = json_data["jobs"]
        job = jobs[0]
        job_options = job["job options"]
        directory = Path(job_options["directory"])
        self.name = directory.name
        self.jobname = job["jobname"]
        self.numjobs = int(job_options["numjobs"])
        self.bs = int(job_options["bs"])
        self.size = int(job_options["size"])
        self.ioengine = job_options["ioengine"]
        self.rw = job_options["rw"]
        self.rwmixwrite = int(job_options["rwmixwrite"])
        job_read = job["read"]
        self.rd_io_bytes = int(job_read["io_bytes"])
        self.rd_bw_bytes = int(job_read["bw_bytes"])
        self.rd_iops = float(job_read["iops"])
        job_read = job["write"]
        self.wr_io_bytes = int(job_read["io_bytes"])
        self.wr_bw_bytes = int(job_read["bw_bytes"])
        self.wr_iops = float(job_read["iops"])


class FioDataSet:
    """
    Map of FioData using num-jobs as key
    """

    def __init__(self) -> None:
        self.cols = ColorLabels()
        self.dset: Dict[int, List[FioData]] = {}
        self.bsk: int = 0
        self.wr_bw_max = 0

    def add(self, fio_data: FioData) -> None:
        self._append_dat(fio_data)
        self._update_bsk(fio_data)
        self._update_wr_bw(fio_data)

    def _append_dat(self, fio_data: FioData) -> None:
        nj = fio_data.numjobs
        fio_data_list = self.dset.get(nj, [])
        fio_data_list.append(fio_data)
        self.dset[nj] = fio_data_list

    def _update_bsk(self, fio_data) -> None:
        self.bsk = max(self.bsk, int(fio_data.bs / 1024))

    def _update_wr_bw(self, fio_data) -> None:
        self.wr_bw_max = max(self.wr_bw_max, fio_data.wr_bw_bytes)


class FioDataSets:
    """
    A map-of-maps of FioData sorted by block-size and num-jobs
    """

    def __init__(self) -> None:
        self.dsets: Dict[int, FioDataSet] = {}

    def add(self, fio_data: FioData) -> None:
        bs = fio_data.bs
        dset = self.dsets.get(bs, FioDataSet())
        dset.add(fio_data)
        self.dsets[bs] = dset

    def loadn(self, jfiles: Iterable[Path]) -> None:
        for jf in jfiles:
            with open(jf, "r", encoding="utf-8") as fd:
                json_data = json.load(fd)
                fio_data = FioData(json_data)
                self.add(fio_data)


def dset_to_plot_labels(dset: FioDataSet) -> List[str]:
    labels: Dict[int, int] = {}
    for nj in dset.dset:
        for fio_data in dset.dset[nj]:
            njobs = fio_data.numjobs
            labels[njobs] = 1
    return [f"njobs={nj}" for nj in sorted(labels)]


def dset_to_plot_subdat(dset: FioDataSet) -> Dict[str, List[int]]:
    ret: Dict[str, List[int]] = {}
    for nj in dset.dset:
        for fio_data in dset.dset[nj]:
            dat = ret.get(fio_data.name, [])
            dat.append(fio_data.wr_bw_bytes)
            ret[fio_data.name] = dat
    return ret


def plot_fio_data(dset: FioDataSet) -> None:
    """
    Plot series of fio output data as I/O performance graph.

    See: https://matplotlib.org/gallery/lines_bars_and_markers/barchart.html
    """
    labels = dset_to_plot_labels(dset)
    subdat = dset_to_plot_subdat(dset)

    x = np.arange(len(labels))
    width = 0.25
    multiplier = 0

    mpl.style.use("bmh")
    fig, ax = plt.subplots()
    fig.set_facecolor("ghostwhite")
    fig.suptitle("I/O Performance Read-Write (rwmix=50%)", fontsize="xx-large")

    for atr, dat in subdat.items():
        offset = width * multiplier
        color = dset.cols.color_of(atr)
        ax.bar(x + offset, dat, width, label=atr, color=color)
        # ax.bar_label(rects, padding=3)
        multiplier += 1

    ax.set_title(f"Block size {dset.bsk}K", fontsize="x-large", pad=15)
    ax.set_ylabel("Write bandwidth (MB/s)", fontsize="large", labelpad=15)
    ax.set_xticks(x + width)
    ax.set_xticklabels(labels)
    ax.legend(loc="upper left")
    ax.set_ylim(0, int(dset.wr_bw_max * 1.1))
    ax.grid(True)
    plt.show()


def plot_fio_bw(dsets: FioDataSets) -> None:
    for _, dset in dsets.dsets.items():
        plot_fio_data(dset)


def input_jsons() -> Iterable[Path]:
    ret = []
    for pathname in sys.argv[1:]:
        jfile = Path(pathname)
        if jfile.is_file() and jfile.suffix == ".json":
            ret.append(jfile)
    return ret


def main():
    dsets = FioDataSets()
    dsets.loadn(input_jsons())
    plot_fio_bw(dsets)


if __name__ == "__main__":
    main()
