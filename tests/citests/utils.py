# SPDX-License-Identifier: GPL-3.0
import contextlib
import os
import pathlib
import shutil
import urllib
import urllib.request


def is_dir(dirpath: pathlib.Path) -> bool:
    return dirpath.is_dir()


def is_reg(filepath: pathlib.Path) -> bool:
    return filepath.is_file()


def is_empty_dir(dirpath: pathlib.Path) -> bool:
    return is_dir(dirpath) and len(list(dirpath.iterdir())) == 0


def empty_dir(dirpath: pathlib.Path) -> None:
    for name in os.listdir(dirpath):
        subpath = os.path.join(dirpath, name)
        if os.path.isdir(subpath):
            shutil.rmtree(subpath)
        else:
            os.remove(subpath)


def try_urlopen(url: str, timeout: int = 5) -> bool:
    try:
        with contextlib.closing(urllib.request.urlopen(url, timeout=timeout)):
            return True
    except urllib.error.URLError:
        return False
