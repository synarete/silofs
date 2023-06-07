# SPDX-License-Identifier: GPL-3.0
import errno
from . import ctx


def test_fill_data(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs(2)
    enospc = 0
    for prefix in _subdirs_list(8, 1):
        tds_all = {}
        counter = 0
        while counter < 2**20 and enospc < 2:
            counter += 1
            name = f"{prefix}{counter}"
            tds = tc.make_tds(2**8, name, 2**22)
            try:
                tds.do_makedirs()
                tds.do_write()
                tds.do_read()
                tds.prune_data()
                tds_all[name] = tds
            except OSError as ex:
                if ex.errno != errno.ENOSPC:
                    raise ex
                enospc += 1
        for _, tds in tds_all.items():
            tds.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs()


def test_fill_meta(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs(2)
    enospc = 0
    for prefix in _subdirs_list(16, 64):
        tds_all = {}
        counter = 0
        while counter < 2**20 and enospc < 2:
            counter += 1
            name = f"{prefix}{counter}"
            tds = tc.make_tds(2**8, name, 2**22)
            try:
                tds.do_makedirs()
                tds.do_write()
                tds.do_read()
                tds.prune_data()
                tds_all[name] = tds
            except OSError as ex:
                if ex.errno != errno.ENOSPC:
                    raise ex
                enospc += 1
        for _, tds in tds_all.items():
            tds.do_unlink()
    tc.exec_umount()
    tc.exec_rmfs()


def _subdirs_list(level1: int, level2: int) -> list[str]:
    ret = []
    for idx1 in range(1, level1):
        for idx2 in range(1, level2):
            ret.extend([f"A{idx1}/B{idx2}"])
    return ret
