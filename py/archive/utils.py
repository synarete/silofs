# SPDX-License-Identifier: GPL-3.0
import shutil
import typing
from pathlib import Path


class ArchiveException(Exception):
    def __init__(self, msg: str) -> None:
        Exception.__init__(self, msg)


def _find_executable(name: str) -> typing.Tuple[Path, bool]:
    """Locate executable program's path by name"""
    xbin = str(shutil.which(name) or "").strip()
    return (Path(xbin), True) if xbin else (Path(""), False)


def _locate_cmd(name: str) -> Path:
    xbin, found = _find_executable(name)
    if not found:
        raise ArchiveException(f"unable to find executable '{name}'")
    return xbin


def locate_silofs_cmd() -> Path:
    return _locate_cmd("silofs")
