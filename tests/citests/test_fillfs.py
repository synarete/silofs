# SPDX-License-Identifier: GPL-3.0
import errno
from . import ctx


def test_fill_data(tc: ctx.TestCtx) -> None:
    tc.exec_setup_fs(2)
    for prefix in ("A", "B", "C"):
        tds_all = {}
        counter = 0
        while counter < 2**20:
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
                break
        for _, tds in tds_all.items():
            tds.do_unlink()
    tc.exec_umount()
