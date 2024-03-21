# SPDX-License-Identifier: GPL-3.0
import copy
import os
import shlex
import subprocess
import typing
from pathlib import Path

from . import log
from . import utils


def _require_executable(name: str) -> Path:
    """Locate executable program's path by name"""
    pp, ok = utils.find_executable(name)
    if not ok:
        raise CmdError(f"failed to find {name}")
    return pp


class CmdError(Exception):
    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        Exception.__init__(self, msg)
        self.output = out[-256:]
        self.retcode = ret


class CmdExec:
    """Generic wrapper over command-line executor"""

    def __init__(self, prog: str, xbin: typing.Optional[Path] = None) -> None:
        self.prog = prog
        if xbin:
            self.xbin = xbin
        else:
            self.xbin = _require_executable(prog)
        self.cwd = "/"

    def execute_sub(self, args, wdir: str = "", timeout: int = 5) -> str:
        """Execute command via subprocess.

        Execute command as sub-process and return its output. Raises CmdError
        upon failure.
        """
        cmd = self._make_cmd(args)
        cwd = self._make_cwd(wdir)
        txt = ""
        exp = False
        log.printsl(f"EXEC: {cmd}")
        with subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=False,
            env=os.environ.copy(),
            universal_newlines=True,
        ) as proc:
            try:
                std_out, std_err = proc.communicate(timeout=timeout)
                out = std_err or std_out
                txt = out.strip()
            except subprocess.TimeoutExpired:
                proc.kill()
                exp = True
            ret = proc.returncode
            if exp:
                raise CmdError("timedout: " + cmd, txt, ret)
            if ret != 0:
                raise CmdError("failed: " + cmd, txt, ret)
        return txt

    def execute_run(self, args, wdir: str = "") -> None:
        """Run command as sub-process without output, raise upon failure"""
        cmd = self._make_cmd(args)
        cwd = self._make_cwd(wdir)
        log.printsl(f"EXEC: {cmd}")
        proc = subprocess.run(shlex.split(cmd), check=True, cwd=cwd)
        if proc.returncode != 0:
            raise CmdError("failed: " + cmd, ret=proc.returncode)

    def _make_cmd(self, args: typing.Iterable[typing.Any]) -> str:
        cmd_xbin = str(self.xbin)
        cmd_args = [str(arg) for arg in args]
        cmd = cmd_xbin + " " + " ".join(cmd_args)
        return cmd.strip()

    def _make_cwd(self, wdir: str = "") -> str:
        return wdir if len(wdir) > 0 else self.cwd


class CmdShell(CmdExec):
    """Wrapper over execution via shell command"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "sh")
        self.env = os.environ.copy()

    def run(
        self,
        cmd: str,
        wdir: typing.Optional[Path] = None,
        xenv: typing.Optional[typing.Mapping[str, str]] = None,
    ) -> int:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(wdir),
            shell=True,
            universal_newlines=True,
            env=self._mkenv(xenv),
        ) as proc:
            ret = proc.wait()
        return ret

    def run_ok(
        self,
        cmd: str,
        wdir: typing.Optional[Path] = None,
        xenv: typing.Optional[typing.Mapping[str, str]] = None,
    ) -> None:
        log.printsl(f"SH: {cmd}")
        ret = self.run(cmd, wdir, xenv)
        if ret != 0:
            raise CmdError("failed: " + cmd, ret=ret)

    def _mkenv(
        self, xenv: typing.Optional[typing.Mapping[str, str]]
    ) -> dict[str, str]:
        env = copy.copy(self.env)
        if xenv:
            for key, val in xenv.items():
                env[key] = val
        return env


class CmdSilofs(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def init(self, repodir: Path) -> None:
        args = ["init", repodir]
        self.execute_sub(args)

    def mkfs(
        self,
        repodir_name: Path,
        size: int,
        password: str,
        sup_groups: bool = False,
        allow_root: bool = False,
    ) -> None:
        giga = 2**30
        args = ["mkfs", repodir_name]
        if (size % giga) == 0:
            gsize = int(size / giga)
            args = args + [f"--size={gsize}G"]
        else:
            args = args + [f"--size={size}"]
        if password:
            args = args + [f"--password={password}"]
        if sup_groups:
            args = args + ["--sup-groups"]
        if allow_root:
            args = args + ["--allow-root"]
        self.execute_sub(args)

    def mount(
        self,
        repodir_name: Path,
        mntpoint: Path,
        password: str,
        allow_hostids: bool = False,
        allow_xattr_acl: bool = False,
        writeback_cache: bool = False,
    ) -> None:
        wb_mode = int(writeback_cache)
        args = ["mount", repodir_name, mntpoint]
        args = args + [f"--writeback-cache={wb_mode}"]
        if allow_hostids:
            args = args + ["--allow-hostids"]
        if allow_xattr_acl:
            args = args + ["--allow-xattr-acl"]
        if password:
            args = args + ["--password", password]
        self.execute_run(args)

    def umount(self, mntpoint: Path) -> None:
        self.execute_run(["umount", mntpoint])

    def lsmnt(self) -> typing.Iterable[Path]:
        mnts = self.execute_sub(["lsmnt"])
        return [Path(mnt) for mnt in mnts.splitlines()]

    def show_version(self, pathname: Path) -> str:
        return self.execute_sub(["show", "version", pathname])

    def show_boot(self, pathname: Path) -> str:
        return self.execute_sub(["show", "boot", pathname])

    def show_proc(self, pathname: Path) -> str:
        return self.execute_sub(["show", "proc", pathname])

    def show_spstats(self, pathname: Path) -> str:
        return self.execute_sub(["show", "spstats", pathname])

    def show_statx(self, pathname: Path) -> str:
        return self.execute_sub(["show", "statx", pathname])

    def snap(self, name: str, pathname: Path, password: str) -> None:
        args = ["snap", "-n", name, pathname]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)

    def snap_offline(
        self, name: str, repodir_name: Path, password: str
    ) -> None:
        args = ["snap", "-n", name, "--offline", repodir_name]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)

    def tune(self, pathname: Path, ftype: int) -> None:
        self.execute_sub(["tune", "--ftype", str(ftype), pathname])

    def rmfs(self, repodir_name: Path, password: str) -> None:
        args = ["rmfs", repodir_name]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)

    def fsck(self, repodir_name: Path, password: str) -> None:
        args = ["fsck", repodir_name]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)


class CmdUnitests(CmdExec):
    """Wrapper over silofs-unitests command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs-unitests")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def run(self, basedir: Path, level: int = 1) -> None:
        args = [basedir, f"--level={level}"]
        self.execute_sub(args, timeout=1200)


class CmdFuntests(CmdExec):
    """Wrapper over silofs-funtests command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs-funtests")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def run(
        self,
        basedir: Path,
        rand: bool = False,
        nostatvfs: bool = False,
    ) -> None:
        args = [str(basedir)]
        if rand:
            args.append("--random")
        if nostatvfs:
            args.append("--nostatvfs")
        self.execute_sub(args, wdir="/", timeout=2400)


class CmdGit(CmdExec):
    """Wrapper over git command-line utility"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "git")

    def version(self) -> str:
        return self.execute_sub(["version"])

    def clone(self, repo: str, dpath: Path) -> int:
        ret = 0
        try:
            self.execute_sub(["clone", repo, dpath], timeout=300)
        except CmdError as ex:
            ret = ex.retcode
        return ret


# pylint: disable=R0903
class Cmds:
    """All command-line wrappers in single class"""

    def __init__(self) -> None:
        self.sh = CmdShell()
        self.silofs = CmdSilofs()
        self.unitests = CmdUnitests()
        self.funtests = CmdFuntests()
        self.git = CmdGit()
