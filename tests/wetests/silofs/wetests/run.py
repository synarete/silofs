# SPDX-License-Identifier: GPL-3.0
from . import ctx
from . import test_basics

TESTS = [test_basics.test_hello]


def run_tests():
    global TESTS
    te = ctx.TestEnv("/", "/")
    te.show_version()
    for t in TESTS:
        print(t)
