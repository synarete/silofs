# SPDX-License-Identifier: GPL-3.0
import contextlib
import inspect
import os
import pathlib
import pprint
import random
import shutil
import urllib
import urllib.request


def selfname() -> str:
    return str(inspect.stack()[1][3])


def is_dir(dirpath: pathlib.Path) -> bool:
    return dirpath.is_dir()


def is_reg(filepath: pathlib.Path) -> bool:
    return filepath.is_file()


def is_empty_dir(dirpath: pathlib.Path) -> bool:
    return is_dir(dirpath) and len(list(dirpath.iterdir())) == 0


def empty_dir(dirpath: pathlib.Path) -> None:
    for name in os.listdir(dirpath):
        subpath = dirpath / name
        if is_dir(subpath):
            rmtree_at(subpath)
        else:
            rmfile_at(subpath)


def rmtree_at(dirpath: pathlib.Path) -> None:
    os.stat(dirpath)
    shutil.rmtree(dirpath)


def rmfile_at(path: pathlib.Path) -> None:
    os.stat(path)
    path.unlink(missing_ok=False)


def fstype_of(path: pathlib.Path) -> str:
    """Resolve file-system type of a given pathname"""
    proc_mounts = pathlib.Path("/proc/mounts").read_text(encoding="utf-8")
    lines = proc_mounts.split("\n")
    st = path.stat()
    for line in lines:
        fields = line.split()
        if len(fields) < 3:
            continue
        mntp = fields[1]
        fs_type = fields[2]
        try:
            mntp_path = pathlib.Path(mntp)
            mntp_st = mntp_path.stat()
            if mntp_st.st_dev == st.st_dev:
                return fs_type
        except OSError:
            continue
    return "unknownfs"


def try_urlopen(url: str, timeout: int = 5) -> bool:
    try:
        with contextlib.closing(urllib.request.urlopen(url, timeout=timeout)):
            return True
    except urllib.error.URLError:
        return False


def _random_bytearray(n: int) -> bytearray:
    return bytearray(random.randbytes(n))


def prandbytes(rsz: int) -> bytes:
    """Generate pseudo-random bytes array."""
    rnd = _random_bytearray(min(rsz, 1024))
    rba = bytearray(rnd)
    while len(rba) < rsz:
        rem = rsz - len(rba)
        if rem <= 1024:
            rnd = _random_bytearray(rem)
            rba = rnd + rba
        elif rem <= 2048:
            rnd = _random_bytearray(1024)
            rba = rnd + rba + rnd
        else:
            rnd = _random_bytearray(1024)
            rba = rnd + rba + rnd + rba
    return rba[:rsz]


def pformat(obj) -> str:
    rep = pprint.pformat(vars(obj), indent=0)
    return rep.replace("\n", " ")
