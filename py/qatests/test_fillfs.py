# SPDX-License-Identifier: GPL-3.0
import errno
from pathlib import Path

from .ctx import TestEnv


def _expect_enospc(ex: OSError) -> None:
    if ex.errno != errno.ENOSPC:
        raise ex


def _unlink_all(pathnames: list[Path]) -> None:
    for path in pathnames:
        path.unlink()


def test_fill_data(env: TestEnv) -> None:
    env.exec_setup_fs(2)
    enospc = 0
    for prefix in _subdirs_list(8, 1):
        pathnames = []
        counter = 0
        while counter < 2**20 and enospc < 2:
            counter += 1
            name = f"{prefix}{counter}"
            tds = env.make_tds(2**8, name, 2**22)
            try:
                tds.do_makedirs()
                tds.do_write()
                tds.do_read()
                pathnames.extend(tds.pathnames())
            except OSError as ex:
                _expect_enospc(ex)
                enospc += 1
        _unlink_all(pathnames)
    env.exec_teardown_fs()


def test_fill_meta(env: TestEnv) -> None:
    env.exec_setup_fs(2)
    enospc = 0
    for prefix in _subdirs_list(16, 64):
        pathnames = []
        counter = 0
        while counter < 2**20 and enospc < 2:
            counter += 1
            name = f"{prefix}{counter}"
            tds = env.make_tds(2**8, name, 2**22)
            try:
                tds.do_makedirs()
                tds.do_write()
                tds.do_read()
                pathnames.extend(tds.pathnames())
            except OSError as ex:
                _expect_enospc(ex)
                enospc += 1
        _unlink_all(pathnames)
    env.exec_teardown_fs()


def _subdirs_list(level1: int, level2: int) -> list[str]:
    ret = []
    for idx1 in range(1, level1):
        for idx2 in range(1, level2):
            ret.extend([f"A{idx1}/B{idx2}"])
    return ret
