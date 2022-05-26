# SPDX-License-Identifier: GPL-3.0
from . import ctx


def test_hello(te: ctx.TestEnv) -> None:
    print(te.mntdir)
