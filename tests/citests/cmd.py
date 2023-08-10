# SPDX-License-Identifier: GPL-3.0
import os
import pathlib
import shlex
import shutil
import subprocess
import typing


def _find_executable(name: str) -> pathlib.Path:
    """Locate executable program's path by name"""
    xbin = shutil.which(name)
    if not xbin:
        raise CmdError(f"failed to find {name}")
    path = pathlib.Path(str(xbin).strip())
    return path


class CmdError(Exception):
    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        Exception.__init__(self, msg)
        self.output = out[-256:]
        self.retcode = ret


class CmdExec:
    """Generic wrapper over command-line executor"""

    def __init__(self, prog: str) -> None:
        self.prog = prog
        self.xbin = _find_executable(prog)
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

    @staticmethod
    def run(cmd: str, wdir=None) -> int:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=wdir,
            shell=True,
            env=os.environ.copy(),
        ) as proc:
            ret = proc.wait()
        return ret

    def run_ok(self, cmd: str, wdir=None) -> None:
        ret = self.run(cmd, wdir)
        if ret != 0:
            raise CmdError("failed: " + cmd, ret=ret)


class CmdSilofs(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def init(self, repodir: pathlib.Path) -> None:
        args = ["init", repodir]
        self.execute_sub(args)

    def mkfs(
        self,
        repodir_name: pathlib.Path,
        size: int,
        password: str,
        sup_groups: bool = False,
        allow_root: bool = False,
    ) -> None:
        args = ["mkfs", "-s", str(size), repodir_name]
        if password:
            args = args + [f"--password={password}"]
        if sup_groups:
            args = args + ["--sup-groups"]
        if allow_root:
            args = args + ["--allow-root"]
        self.execute_sub(args)

    def mount(
        self,
        repodir_name: pathlib.Path,
        mntpoint: pathlib.Path,
        password: str,
        allow_hostids: bool = False,
        writeback_cache: bool = False,
    ) -> None:
        wb_mode = int(writeback_cache)
        args = ["mount", repodir_name, mntpoint]
        args = args + [f"--writeback-cache={wb_mode}"]
        if allow_hostids:
            args = args + ["--allow-hostids"]
        if password:
            args = args + ["--password", password]
        self.execute_run(args)

    def umount(self, mntpoint: pathlib.Path) -> None:
        self.execute_run(["umount", mntpoint])

    def show_version(self, pathname: pathlib.Path) -> str:
        return self.execute_sub(["show", "version", pathname])

    def show_boot(self, pathname: pathlib.Path) -> str:
        return self.execute_sub(["show", "boot", pathname])

    def show_proc(self, pathname: pathlib.Path) -> str:
        return self.execute_sub(["show", "proc", pathname])

    def show_spstats(self, pathname: pathlib.Path) -> str:
        return self.execute_sub(["show", "spstats", pathname])

    def show_statx(self, pathname: pathlib.Path) -> str:
        return self.execute_sub(["show", "statx", pathname])

    def snap(self, name: str, pathname: pathlib.Path) -> None:
        self.execute_sub(["snap", "-n", name, pathname])

    def snap_offline(
        self, name: str, repodir_name: pathlib.Path, password: str
    ) -> None:
        args = ["snap", "-n", name, "--offline", repodir_name]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)

    def rmfs(self, repodir_name: pathlib.Path, password: str) -> None:
        args = ["rmfs", repodir_name]
        if password:
            args = args + ["--password", password]
        self.execute_sub(args)

    def fsck(self, repodir_name: pathlib.Path, password: str) -> None:
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

    def run(self, basedir: pathlib.Path, level: int = 1) -> None:
        args = [basedir, f"--level={level}"]
        self.execute_sub(args, timeout=1200)


class CmdFftests(CmdExec):
    """Wrapper over silofs-fftests command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs-fftests")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def run(
        self,
        basedir: pathlib.Path,
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

    def clone(self, repo: str, dpath: pathlib.Path) -> int:
        ret = 0
        try:
            self.execute_sub(["clone", repo, dpath], timeout=60)
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
        self.fftests = CmdFftests()
        self.git = CmdGit()
