# SPDX-License-Identifier: GPL-3.0

class Env:
    def __init__(self) -> None:
        self.basedir = "/"

    def show(self) -> None:
        print(self.basedir)
