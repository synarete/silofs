# SPDX-License-Identifier: GPL-3.0
import os
import shutil


def is_dir(dirpath: str) -> bool:
    return os.path.isdir(dirpath)


def is_empty_dir(dirpath: str) -> bool:
    return is_dir(dirpath) and not os.listdir(dirpath)


def empty_dir(dirpath: str) -> None:
    for name in os.listdir(dirpath):
        subpath = os.path.join(dirpath, name)
        if os.path.isdir(subpath):
            shutil.rmtree(subpath)
        else:
            os.remove(subpath)
