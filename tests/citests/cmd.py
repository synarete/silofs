# SPDX-License-Identifier: GPL-3.0
import os
import shlex
import shutil
import subprocess
import typing


class CmdError(Exception):
    pass


class CmdExec:
    """Generic wrapper over command-line executor"""

    def __init__(self, prog: str) -> None:
        self.prog = prog
        self.xbin = self.find_executable(prog)

    def execute(self, args, wdir=None) -> str:
        """Execute command as sub-process, raise upon failure"""
        cmd = self._make_cmd(args)
        with subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=wdir,
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
        return ret.strip()

    def execute2(self, args, sh: bool = False, wdir: str = None) -> None:
        """Run command as sub-process without output, raise upon failure"""
        cmd = self._make_cmd(args)
        proc = subprocess.run(shlex.split(cmd), check=True, shell=sh, cwd=wdir)
        if proc.returncode != 0:
            raise CmdError("failed: " + cmd)

    def execute3(self, args, sh: bool = False, wdir=None) -> int:
        """Execute command as sub-process and return its exit status code"""
        cmd = self._make_cmd(args)
        with subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=wdir,
            shell=sh,
            env=os.environ.copy(),
        ) as proc:
            ret = proc.wait()
        return ret

    def execute4(self, args, wdir=None) -> None:
        ret = self.execute3(args, wdir)
        if ret != 0:
            raise CmdError("failed: " + self._make_cmd(args))

    def _make_cmd(self, args: typing.Iterable[str]) -> str:
        return self.xbin + " " + " ".join(args)

    @staticmethod
    def find_executable(name: str) -> str:
        """locate executable program's path by name"""
        xbin = shutil.which(name)
        if not xbin:
            raise CmdError("failed to find " + name)
        return str(xbin).strip()


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
            raise CmdError("failed: " + cmd)


class CmdSilofs(CmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs")

    def version(self) -> str:
        return self.execute(["-v"])

    def init(self, repodir: str, attic: bool = False) -> None:
        args = ["init", repodir]
        if attic:
            args.append("--attic")
        self.execute2(args)

    def mkfs(self, repodir_name: str, size: int) -> None:
        self.execute2(["mkfs", "-s", str(size), repodir_name])

    def mount(
        self, repodir_name: str, mntpoint: str, allow_hostids: bool = False
    ) -> None:
        args = ["mount", repodir_name, mntpoint]
        if allow_hostids:
            args.append("--allow-other")
            args.append("--allow-hostids")
        self.execute2(args)

    def umount(self, mntpoint: str) -> None:
        self.execute2(["umount", mntpoint])

    def show_version(self, pathname: str) -> str:
        return self.execute(["show", "version", pathname])

    def show_boot(self, pathname: str) -> str:
        return self.execute(["show", "boot", pathname])

    def show_prstats(self, pathname: str) -> str:
        return self.execute(["show", "prstats", pathname])

    def show_spstats(self, pathname: str) -> str:
        return self.execute(["show", "spstats", pathname])

    def show_statx(self, pathname: str) -> str:
        return self.execute(["show", "statx", pathname])

    def snap(self, name: str, pathname: str) -> None:
        return self.execute2(["snap", "-n", name, pathname])

    def snap2(self, name: str, repodir_name: str) -> None:
        self.execute2(["snap", "-n", name, "--offline", repodir_name])

    def rmfs(self, repodir_name: str) -> None:
        self.execute2(["rmfs", repodir_name])

    def fsck(self, repodir_name: str) -> None:
        self.execute2(["fsck", repodir_name])

    def archive(self, repodir_name: str, atticdir_name: str, pw: str) -> None:
        self.execute2(["archive", "-p", pw, repodir_name, atticdir_name])

    def restore(self, atticdir_name: str, repodir_name: str, pw: str) -> None:
        self.execute2(["restore", "-p", pw, atticdir_name, repodir_name])


class CmdUnitests(CmdExec):
    """Wrapper over silofs-unitests command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs-unitests")

    def version(self) -> str:
        return self.execute(["-v"])

    def run(self, basedir: str, level: int = 1) -> None:
        args = [basedir, f"--level={level}"]
        ret = self.execute3(args)
        if ret != 0:
            raise CmdError("unitests failed")


class CmdVfstests(CmdExec):
    """Wrapper over silofs-vfstests command-line front-end"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "silofs-vfstests")

    def version(self) -> str:
        return self.execute(["-v"])

    def run(self, basedir: str, rand: bool = False) -> None:
        args = [basedir]
        if rand:
            args.append("-r")
        ret = self.execute3(args, wdir="/")
        if ret != 0:
            raise CmdError("vfstests failed")


class CmdGit(CmdExec):
    """Wrapper over git command-line utility"""

    def __init__(self) -> None:
        CmdExec.__init__(self, "git")

    def version(self) -> str:
        return self.execute(["version"])

    def clone(self, repo: str, dpath: str) -> int:
        return self.execute3(["clone", repo, dpath])


# pylint: disable=R0903
class Cmds:
    """All command-line wrappers in single class"""

    def __init__(self) -> None:
        self.sh = CmdShell()
        self.silofs = CmdSilofs()
        self.unitests = CmdUnitests()
        self.vfstests = CmdVfstests()
        self.git = CmdGit()
