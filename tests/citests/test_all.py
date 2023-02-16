# SPDX-License-Identifier: GPL-3.0
from . import ctx
from . import test_basic
from . import test_io
from . import test_snap
from . import test_fsck
from . import test_self
from . import test_xprogs


TESTS = [
    test_basic.test_version,
    test_basic.test_init,
    test_basic.test_mkfs,
    test_basic.test_mount,
    test_basic.test_hello_world,
    test_basic.test_fscapacity,
    test_basic.test_show,
    test_io.test_rw_text,
    test_io.test_rw_rands,
    test_io.test_reload,
    test_io.test_reload_n,
    test_self.test_unit_tests,
    test_self.test_vfs_tests,
    test_self.test_vfs_tests2,
    test_snap.test_snap_basic,
    test_snap.test_snap_reload,
    test_fsck.test_fsck_basic,
    test_fsck.test_fsck_snap,
    test_xprogs.test_postgresql,
    test_xprogs.test_rsync,
    test_xprogs.test_gitscm,
]


def get_tests_defs() -> list[ctx.TestDef]:
    return [ctx.TestDef(test) for test in TESTS]
