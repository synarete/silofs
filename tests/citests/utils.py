# SPDX-License-Identifier: GPL-3.0
import contextlib
import os
import shutil
import urllib
import urllib.request


def is_dir(dirpath: str) -> bool:
    return os.path.isdir(dirpath)


def is_reg(filepath: str) -> bool:
    return os.path.isfile(filepath)


def is_empty_dir(dirpath: str) -> bool:
    return is_dir(dirpath) and not os.listdir(dirpath)


def empty_dir(dirpath: str) -> None:
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
