# SPDX-License-Identifier: GPL-3.0
from .context import Env

def test_hello(env: Env) -> None:
    print("hello, world")
    print(env.basedir)
