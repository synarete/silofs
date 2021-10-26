#!/usr/bin/env python3

import sys
import os
import math
import cycler
import itertools
import matplotlib as mpl
import matplotlib.pyplot as plt


# For fio minimal output format, see:
#  https://fio.readthedocs.io/en/latest/fio_doc.html
#  https://www.andypeace.com/fio_minimal.html
class FioDat:

    def __init__(self, csv) -> None:

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
                fio_data.append(FioDat(csv))
            line = fp.readline()
    return fio_data


def align_to(val, align):
    return math.floor((val + align + 1) / align) * align


def calc_max_iops_lat(fio_data):
    iops_max = 0
    lat_max = 0
    for fio_dat in fio_data:
        lat_max = max(lat_max, fio_dat.wr_lat)
        iops_max = max(iops_max, fio_dat.wr_iops)
    return (align_to(iops_max, 100000), align_to(lat_max, 10.0))


def fio_jobs_to_dots(fio_data):
    wr_iops = []
    wr_lat = []
    for fio_dat in fio_data:
        wr_iops.append(fio_dat.wr_iops)
        wr_lat.append(fio_dat.wr_lat)
    return (wr_iops, wr_lat)


def fio_data_to_dict(fio_data):
    dic = {}
    for fio_dat in fio_data:
        dic.setdefault(fio_dat.tag, []).append(fio_dat)
    return dic


def plot_fio_jobs(fio_data):
    mpl.style.use('bmh')
    fig, ax = plt.subplots()
    fig.set_facecolor('ghostwhite')
    fig.suptitle('Performance (IOPs/Latency)', fontsize='xx-large')
    ax.set_title('CPUs: 1 2 4 8 16 32', fontsize='x-large', pad=15)
    ax.set_xlabel('IOPS (8K randrw)', fontsize='large', labelpad=15)
    ax.set_ylabel('Latency (us)', fontsize='large', labelpad=15)
    (iops_max, lat_max) = calc_max_iops_lat(fio_data)
    ax.set(xlim=(0, iops_max))
    ax.set(ylim=(0, lat_max))
    ax.grid(True)
    ax.set_prop_cycle(cycler.cycler('color', ['b', 'r', 'g', 'y', 'c', 'm']))
    fio_data_dic = fio_data_to_dict(fio_data)
    for name in fio_data_dic:
        (wr_iops, wr_lat) = fio_jobs_to_dots(fio_data_dic[name])
        ax.plot(wr_iops, wr_lat, marker='o', linestyle='solid', linewidth=2,
                markersize=5, label=name)
    ax.legend()
    plt.show()


def main():
    fio_data = []
    for csvfile in sys.argv[1:]:
        if os.path.isfile(csvfile):
            fio_data.append(parse_fio_csv(csvfile))
    fio_data = list(itertools.chain.from_iterable(fio_data))
    plot_fio_jobs(fio_data)


if __name__ == '__main__':
    main()
