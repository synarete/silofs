# SPDX-License-Identifier: GPL-3.0
from . import ctx
from . import test_archive
from . import test_basic
from . import test_fillfs
from . import test_fio
from . import test_fsck
from . import test_io
from . import test_self
from . import test_snap
from . import test_view
from . import test_xprogs

TESTS = [
    test_basic.test_version,
    test_basic.test_init,
    test_basic.test_mkfs,
    test_basic.test_mount,
    test_basic.test_hello_world,
    test_basic.test_fscapacity,
    test_basic.test_show,
    test_basic.test_mkfs_mount_with_opts,
    test_io.test_rw_text,
    test_io.test_rw_rands,
    test_self.test_unitests,
    test_io.test_reload,
    test_io.test_reload_n,
    test_io.test_async_io,
    test_view.test_view_minimal,
    test_view.test_view_data,
    test_snap.test_snap_basic,
    test_snap.test_snap_reload_twice,
    test_snap.test_snap_reload_multi,
    test_snap.test_snap_offline,
    test_snap.test_snap_repeated,
    test_fsck.test_fsck_basic,
    test_fsck.test_fsck_snap,
    test_archive.test_archive_basic,
    test_archive.test_archive_twice,
    test_fillfs.test_fill_data,
    test_fillfs.test_fill_meta,
    test_self.test_cicd,
    test_self.test_funtests,
    test_self.test_funtests_nosplice,
    test_self.test_funtests_tune2,
    test_self.test_funtests_mt,
    test_fio.test_fio_simple,
    test_fio.test_fio_njobs,
    test_xprogs.test_postgresql,
    test_xprogs.test_rsync,
    test_xprogs.test_findutils,
    test_xprogs.test_gitscm,
    test_xprogs.test_git_archive_untar,
    test_xprogs.test_rpmbuild,
]


def get_tests_defs() -> list[ctx.TestDef]:
    return [ctx.TestDef(test) for test in TESTS]
