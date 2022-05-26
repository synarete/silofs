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

    def execute_mute(self, args: typing.Iterable[str]) -> None:
        out = self.execute(args)
        if out:
            raise CmdError("unexpected output: " + out)

    def execute(self, args: typing.Iterable[str]) -> str:
        cmd = self.xbin + " " + " ".join(args)
        return _sub_exec(cmd).strip()


class Cmd(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self.execute(["-v"])

    def init(self, repodir: str) -> None:
        self.execute_mute(["init", repodir])

    def mkfs(self, repodir_name: str, size: int) -> None:
        self.execute_mute(["mkfs", "-s", str(size), repodir_name])

    def mount(self, repodir_name: str, mntpoint: str) -> None:
        self.execute_mute(["mount", repodir_name, mntpoint])

    def umount(self, mntpoint: str) -> None:
        self.execute_mute(["mount", mntpoint])


def _locate_bin(name: str) -> str:
    """locate executable program's path by name"""
    xbin = distutils.spawn.find_executable(name)
    if not xbin:
        raise CmdError("failed to find " + name)
    return str(xbin).strip()


def _sub_exec(cmd, work_dir=None) -> str:
    """Execute command as sub-process, raise upon failure"""
    ret = ""
    with subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=work_dir,
        shell=False,
        env=os.environ.copy(),
    ) as pipes:
        std_out, std_err = pipes.communicate()
        if pipes.returncode != 0:
            raise CmdError("failed: " + cmd)
        out = std_err or std_out
        ret = out.decode("UTF-8")
    return ret
