# SPDX-License-Identifier: GPL-3.0
import typing
from pathlib import Path

from . import utils


class ExpectException(Exception):
    pass


class Expect:
    def __init__(self, name: str) -> None:
        self.name = name

    def error(self, msg: str) -> typing.NoReturn:
        xmsg = self.name + ": " + msg if self.name else msg
        raise ExpectException(xmsg)

    def ok(self, status) -> None:
        if status != 0:
            self.error(f"not ok: status={status}")

    def eq(self, a, b) -> None:
        if a != b:
            sa = self._stringify(a)
            sb = self._stringify(b)
            self.error(f"not equal: {sa} != {sb}")

    def gt(self, a, b) -> None:
        if a <= b:
            sa = self._stringify(a)
            sb = self._stringify(b)
            self.error(f"not greater-than: {sa} <= {sb}")

    def within(self, elem, xset) -> None:
        if elem not in xset:
            self.error(f"'{elem}' not found in '{xset}'")

    def exists(self, path: Path) -> None:
        if not path.exists():
            self.error(f"not exists: {path}")

    def not_exists(self, path: Path) -> None:
        if path.exists():
            self.error(f"already exists: {path}")

    def is_dir(self, path: Path) -> None:
        if not path.is_dir():
            self.error(f"not a directory: {path}")

    def is_reg(self, path: Path) -> None:
        if not path.is_file():
            self.error(f"not a regular file: {path}")

    def empty_dir(self, dirpath: Path) -> None:
        if not utils.is_empty_dir(dirpath):
            self.error(f"not an empty directory: {dirpath}")

    @staticmethod
    def _stringify(x):
        s = str(x)
        if len(s) > 24:
            s = s[0:20] + "..."
        return s
