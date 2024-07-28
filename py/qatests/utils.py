# SPDX-License-Identifier: GPL-3.0
import contextlib
import inspect
import os
import pprint
import random
import shutil
import typing
import urllib
import urllib.request
from pathlib import Path


def selfname() -> str:
    return str(inspect.stack()[1][3])


def is_dir(dirpath: Path) -> bool:
    return dirpath.is_dir()


def is_reg(filepath: Path) -> bool:
    return filepath.is_file()


def is_empty_dir(dirpath: Path) -> bool:
    return is_dir(dirpath) and len(list(dirpath.iterdir())) == 0


def empty_dir(dirpath: Path) -> None:
    for name in os.listdir(dirpath):
        subpath = dirpath / name
        if is_dir(subpath):
            rmtree_at(subpath)
        else:
            rmfile_at(subpath)


def rmtree_at(dirpath: Path) -> None:
    os.stat(dirpath)
    shutil.rmtree(dirpath)


def rmfile_at(path: Path) -> None:
    os.stat(path)
    path.unlink(missing_ok=False)


def fstype_of(path: Path) -> str:
    """Resolve file-system type of a given pathname"""
    proc_mounts = Path("/proc/mounts").read_text(encoding="utf-8")
    lines = proc_mounts.split("\n")
    st = path.stat()
    for line in lines:
        fields = line.split()
        if len(fields) < 3:
            continue
        mntp = fields[1]
        fs_type = fields[2]
        try:
            mntp_path = Path(mntp)
            mntp_st = mntp_path.stat()
            if mntp_st.st_dev == st.st_dev:
                return fs_type
        except OSError:
            continue
    return "unknownfs"


def try_urlopen(url: str, timeout: int = 5) -> bool:
    try:
        urlopen = urllib.request.urlopen
        with contextlib.closing(urlopen(url, timeout=timeout)):
            return True
    except urllib.error.URLError:
        return False


def try_urlread_some(url: str, timeout: int = 5) -> bool:
    try:
        urlopen = urllib.request.urlopen
        with contextlib.closing(urlopen(url, timeout=timeout)) as fh:
            dat = fh.read()
            return len(dat) > 0
    except urllib.error.URLError:
        return False


def _random_bytearray(n: int) -> bytearray:
    return bytearray(random.randbytes(n))


def prandbytes(rsz: int) -> bytes:
    """Generate pseudo-random bytes array."""
    rba = _random_bytearray(min(rsz, 1024))
    while len(rba) < rsz:
        rem = rsz - len(rba)
        rnd = _random_bytearray(min(rem, 1024))
        rba = rba + rnd + rba
    return rba[:rsz]


def pformat(obj) -> str:
    """Wrapper over formatted pretty-print"""
    rep = pprint.pformat(vars(obj), indent=0)
    return rep.replace("\n", " ")


def find_executable(name: str) -> typing.Tuple[Path, bool]:
    """Locate executable program's path by name"""
    xbin = str(shutil.which(name) or "").strip()
    return (Path(xbin), True) if xbin else (Path(""), False)


def has_executables(names: typing.Iterable[str]) -> bool:
    """Returns True is able to find all executable programs path by name"""
    for name in names:
        _, ok = find_executable(name)
        if not ok:
            return False
    return True
