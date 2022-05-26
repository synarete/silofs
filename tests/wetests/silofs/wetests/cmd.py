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
        self.xbin = CmdExec._locate_bin(self.prog)

    def _execute_mute(self, args: typing.Iterable[str]) -> None:
        out = self._execute(args)
        if len(out):
            raise CmdError("unexpected output: " + out)

    def _execute(self, args: typing.Iterable[str]) -> str:
        cmd = self.xbin + " " + " ".join(args)
        return Cmd._subexec(cmd).strip()

    @staticmethod
    def _locate_bin(name: str) -> str:
        xbin = distutils.spawn.find_executable(name)
        if not xbin:
            raise CmdError("failed to find " + name)
        return str(xbin).strip()

    @staticmethod
    def _subexec(cmd, work_dir=None) -> str:
        """Execute command as sub-process, raise upon failure"""
        pipes = subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=work_dir,
            shell=False,
            env=os.environ.copy(),
        )
        std_out, std_err = pipes.communicate()
        if pipes.returncode != 0:
            raise CmdError("failed: " + cmd)
        out = std_err or std_out
        return out.decode("UTF-8")


class Cmd(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self._execute(["-v"])

    def init(self, repodir: str) -> None:
        self._execute_mute(["init", repodir])

    def mkfs(self, repodir_name: str, size: int) -> None:
        self._execute_mute(["mkfs", "-s", repodir_name])

    def mount(self, repodir_name: str, mntpoint: str) -> None:
        self._execute_mute(["mount", repodir_name, mntpoint])

    def umount(self, mntpoint: str) -> None:
        self._execute_mute(["mount", mntpoint])
