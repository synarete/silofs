# SPDX-License-Identifier: GPL-3.0
import os
import shlex
import subprocess
import distutils.spawn
import typing


class CmdError(Exception):
    pass


class CmdExec:
    """Generic wrapper over command-line executor"""

    def __init__(self, prog: str) -> None:
        self.prog = prog
        self.xbin = _locate_bin(self.prog)

    def execute(self, args: typing.Iterable[str]) -> str:
        return _subproc_comm(self._make_cmd(args)).strip()

    def execute2(self, args: typing.Iterable[str]) -> None:
        _subproc_run(self._make_cmd(args))

    def _make_cmd(self, args: typing.Iterable[str]) -> str:
        return self.xbin + " " + " ".join(args)


class Cmd(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self.execute(["-v"])

    def init(self, repodir: str) -> None:
        self.execute2(["init", repodir])

    def mkfs(self, repodir_name: str, size: int) -> None:
        self.execute2(["mkfs", "-s", str(size), repodir_name])

    def mount(self, repodir_name: str, mntpoint: str) -> None:
        self.execute2(["mount", repodir_name, mntpoint])

    def umount(self, mntpoint: str) -> None:
        self.execute2(["umount", mntpoint])


def _locate_bin(name: str) -> str:
    """locate executable program's path by name"""
    xbin = distutils.spawn.find_executable(name)
    if not xbin:
        raise CmdError("failed to find " + name)
    return str(xbin).strip()


def _subproc_run(cmd: str, work_dir=None) -> None:
    """Execute command as sub-process, raise upon failure"""
    proc = subprocess.run(shlex.split(cmd), check=True, cwd=work_dir)
    if proc.returncode != 0:
        raise CmdError("failed: " + cmd)


def _subproc_comm(cmd: str, work_dir=None) -> str:
    """Execute command as sub-process, raise upon failure"""
    ret = ""
    with subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=work_dir,
        shell=False,
        env=os.environ.copy(),
    ) as proc:
        try:
            std_out, std_err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            std_out, std_err = proc.communicate()
        if proc.returncode != 0:
            raise CmdError("failed: " + cmd)
        out = std_err or std_out
        ret = out.decode("UTF-8")
    return ret
