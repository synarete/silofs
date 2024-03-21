# SPDX-License-Identifier: GPL-3.0
import os
import shlex
import subprocess
import typing
from pathlib import Path

from . import utils


class SilofsCmdError(utils.ArchiveException):
    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        utils.ArchiveException.__init__(self, msg)
        self.output = out[-256:]
        self.retcode = ret


class SilofsCmd:
    """Wrapper over silofs command-line interface via sub-process"""

    def __init__(self) -> None:
        self.xbin = utils.locate_silofs_cmd()
        self.cwd = "/"

    def exec_version(self) -> str:
        return self._execute_sub(["-v"])

    def exec_view(
        self, repodir_name: Path, password: str
    ) -> typing.Iterable[str]:
        args = ["view", "--no-prompt", repodir_name]
        outdat = self._execute_sub(args, indat=password, timeout=30)
        return outdat.split("\n")

    def exec_export(self, repodir: Path, ref: str, outfile: Path) -> None:
        args = ["export", "--ref", ref, "--outfile", outfile, repodir]
        self._execute_run(args, timeout=60)

    def _execute_sub(
        self,
        args,
        wdir: str = "",
        indat: str = "",
        timeout: float = 5.0,
    ) -> str:
        """Execute command via subprocess.

        Execute command as sub-process and return its output. Raises CmdError
        upon failure.
        """
        cmd = self._make_cmd(args)
        cwd = self._make_cwd(wdir)
        txt = ""
        exp = False
        stdin = subprocess.PIPE if indat else None
        with subprocess.Popen(
            shlex.split(cmd),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=False,
            env=os.environ.copy(),
            universal_newlines=True,
        ) as proc:
            try:
                std_out, std_err = proc.communicate(
                    timeout=timeout, input=indat
                )
                out = std_err or std_out
                txt = out.strip()
            except subprocess.TimeoutExpired:
                proc.kill()
                exp = True
            ret = proc.returncode
            if exp:
                raise SilofsCmdError("timedout: " + cmd, txt, ret)
            if ret != 0:
                raise SilofsCmdError("failed: " + cmd, txt, ret)
        return txt

    def _execute_run(self, args, wdir: str = "", timeout: float = 5.0) -> None:
        """Run command as sub-process without output, raise upon failure"""
        cmd = self._make_cmd(args)
        cwd = self._make_cwd(wdir)
        proc = subprocess.run(
            shlex.split(cmd), check=True, cwd=cwd, timeout=timeout
        )
        if proc.returncode != 0:
            raise SilofsCmdError("failed: " + cmd, ret=proc.returncode)

    def _make_cmd(self, args: typing.Iterable[typing.Any]) -> str:
        cmd_xbin = str(self.xbin)
        cmd_args = [str(arg) for arg in args]
        cmd = cmd_xbin + " " + " ".join(cmd_args)
        return cmd.strip()

    def _make_cwd(self, wdir: str = "") -> str:
        return wdir if len(wdir) > 0 else self.cwd
