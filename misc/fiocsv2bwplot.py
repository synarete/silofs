#!/usr/bin/env python3

import sys
import os
import math
import itertools
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# For fio minimal output format, see:
#  https://fio.readthedocs.io/en/latest/fio_doc.html
#  https://www.andypeace.com/fio_minimal.html


class FioData:

    def __init__(self, csv) -> None:
        '''Converts raw fio csv output into python object repr'''
        fields = ['0'] + csv.split(';')
        self.rd_kb = int(fields[6])
        self.rd_bw = int(fields[7])
        self.rd_iops = int(fields[8])
        self.rd_lat = float(fields[40])
        self.wr_kb = int(fields[47])
        self.wr_bw = int(fields[48])
        self.wr_iops = int(fields[49])
        self.wr_lat = float(fields[81])
        job_name = str(fields[3])
        self.job_name = job_name
        job_subs = job_name.split('-')
        self.tag = str(job_subs[0]).replace('_', '-')
        self.bsk = int(job_subs[1].replace('bs', ''))
        self.bs = self.bsk * 1024
        self.jobs = int(job_subs[2].replace('jobs', ''))
        self.name = '{}-{}K'.format(self.tag, self.bsk)


def parse_fio_csv(filepath):
    fio_data = []
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            csv = line.strip()
            if csv and not csv.startswith('#'):
                fio_data.append(FioData(csv))
            line = fp.readline()
    return fio_data


def calc_max_bw(fio_data):
    rd_bw_max = 0
    wr_bw_max = 0
    for fio_dat in fio_data:
        rd_bw_max = max(rd_bw_max, fio_dat.rd_bw / 1024)
        wr_bw_max = max(wr_bw_max, fio_dat.wr_bw / 1024)
    return (rd_bw_max, wr_bw_max)


def calc_max_bw_any(fio_data):
    (rd_bw_max, wr_bw_max) = calc_max_bw(fio_data)
    return max(rd_bw_max, wr_bw_max) + 100


def fio_bw_to_bars(fio_data_list):
    rd_dic = {}
    for fio_dat in fio_data_list:
        bsk = fio_dat.bsk
        tag = '{}-{}k-rd'.format(fio_dat.tag, bsk)
        dat = (tag, bsk, fio_dat.rd_bw / 1024)
        rd_dic.setdefault(bsk, []).append((tag, fio_dat.rd_bw / 1024))
    wr_dic = {}
    for fio_dat in fio_data_list:
        bsk = fio_dat.bsk
        tag = '{}-{}k-wr'.format(fio_dat.tag, bsk)
        dat = (tag, bsk, fio_dat.wr_bw / 1024)
        wr_dic.setdefault(bsk, []).append((tag, fio_dat.wr_bw / 1024))
    return (rd_dic, wr_dic)


def color_labels_of(fio_data):
    dic = {}
    for fio_dat in fio_data:
        dic.setdefault(fio_dat.tag, []).append(fio_dat)
    length = len(dic.keys())

    rd_colors = ['lightsteelblue', 'lavender', 'mediumpurple', 'thistle']
    wr_colors = ['lightsalmon', 'mistyrose', 'coral', 'peru']

    return (itertools.cycle(rd_colors[0:length]),
            itertools.cycle(wr_colors[0:length]))


def plot_fio_bw(fio_data):
    mpl.style.use('bmh')
    fig, ax = plt.subplots()
    fig.set_facecolor('ghostwhite')
    fig.suptitle('I/O Preformance', fontsize='xx-large')
    ax.set_title('Silofs vs in-Kernel File-system', fontsize='x-large', pad=15)
    ax.set_xlabel('Block size', fontsize='large', labelpad=15)
    ax.set_ylabel('Bandwidth (MB/s)', fontsize='large', labelpad=15)
    ax.set(ylim=(0, calc_max_bw_any(fio_data)))
    ax.grid(True)
    ax.legend()
    (rd_colors, wr_colors) = color_labels_of(fio_data)
    (rd_dic, wr_dic) = fio_bw_to_bars(fio_data)
    for bks in rd_dic.keys():
        for bar in rd_dic[bks]:
            color = next(rd_colors)
            ax.bar(bar[0], bar[1], width=0.5, color=color, edgecolor='gray')
    for bks in wr_dic.keys():
        for bar in wr_dic[bks]:
            color = next(wr_colors)
            ax.bar(bar[0], bar[1], width=0.5, color=color, edgecolor='gray')
    plt.show()


def fio_csv_to_data(csvs):
    fio_data = []
    for csvfile in csvs:
        if os.path.isfile(csvfile):
            fio_data.append(parse_fio_csv(csvfile))
    return list(itertools.chain.from_iterable(fio_data))


def main():
    fio_data = fio_csv_to_data(sys.argv[1:])
    plot_fio_bw(fio_data)


if __name__ == '__main__':
    main()
