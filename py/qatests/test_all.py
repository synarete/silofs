# SPDX-License-Identifier: GPL-3.0
import itertools

from . import ctx
from . import test_basic
from . import test_clone
from . import test_fillfs
from . import test_fio
from . import test_fsck
from . import test_io
from . import test_self
from . import test_view
from . import test_xprogs


def list_tests() -> list[ctx.TestDef]:
    tests = [
        test_basic.list_tests(),
        test_io.list_tests(),
        test_view.list_tests(),
        test_clone.list_tests(),
        test_fsck.list_tests(),
        test_fillfs.list_tests(),
        test_self.list_tests(),
        test_fio.list_tests(),
        test_xprogs.list_tests(),
    ]
    return list(itertools.chain.from_iterable(tests))
