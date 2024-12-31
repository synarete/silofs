# SPDX-License-Identifier: GPL-3.0
import copy
import os
import shlex
import subprocess
import typing
from pathlib import Path
from uuid import UUID

from . import log
from . import utils


def _require_executable(name: str) -> Path:
    """Locate executable program's path by name"""
    pp, ok = utils.find_executable(name)
    if not ok:
        raise SubcmdError(f"failed to find {name}")
    return pp


class SubcmdError(Exception):
    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        Exception.__init__(self, msg)
        self.output = out[-1024:]
        self.retcode = ret


class SubcmdExec:
    """Generic wrapper over command-line executor"""

    def __init__(self, prog: str, xbin: typing.Optional[Path] = None) -> None:
        self.prog = prog
        if xbin:
            self.xbin = xbin
        else:
            self.xbin = _require_executable(prog)
        self.cwd = Path("/")

    def execute_sub(
        self,
        args,
        wdir: typing.Optional[Path] = None,
        indat: str = "",
        timeout: float = 5.0,
    ) -> str:
        """Execute command via subprocess.

        Execute command as sub-process and return its output. Raises CmdError
        upon failure.
        """
        txt = ""
        exp = False
        cmd = self._make_cmdline(args)
        self.logcmd("EXEC", cmd, wdir)
        with subprocess.Popen(
            shlex.split(cmd),
            stdin=subprocess.PIPE if indat else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self._getcwd_of(wdir),
            shell=False,
            env=os.environ.copy(),
            universal_newlines=True,
        ) as proc:
            try:
                std_out, std_err = proc.communicate(
                    timeout=timeout, input=indat or None
                )
                out = std_err or std_out
                txt = out.strip()
            except subprocess.TimeoutExpired:
                proc.kill()
                exp = True
            ret = proc.returncode
            if exp:
                raise SubcmdError("timedout: " + cmd, txt, ret)
            if ret != 0:
                raise SubcmdError("failed: " + cmd, txt, ret)
        return txt

    def execute_run(
        self, args, wdir: typing.Optional[Path] = None, indat: str = ""
    ) -> None:
        """Run command as sub-process without output, raise upon failure"""
        cmd = self._make_cmdline(args)
        self.logcmd("EXEC", cmd, wdir)
        ret = subprocess.run(
            shlex.split(cmd),
            check=True,
            cwd=self._getcwd_of(wdir),
            input=indat,
            encoding="utf-8",
        ).returncode
        if ret != 0:
            raise SubcmdError("failed: " + cmd, ret=ret)

    def _make_cmdline(self, args: typing.Iterable[typing.Any]) -> str:
        cmdline_xbin = str(self.xbin)
        cmdline_args = [str(arg) for arg in args]
        cmdline = cmdline_xbin + " " + " ".join(cmdline_args)
        return cmdline.strip()

    def _getcwd_of(self, wdir: typing.Optional[Path] = None) -> Path:
        return wdir if wdir else self.cwd

    def logcmd(
        self, prefix: str, cmd: str, wdir: typing.Optional[Path] = None
    ) -> None:
        """Log out execution sub-command."""
        suffix = ""
        if wdir:
            wd = self._getcwd_of(wdir)
            suffix = f" (wd: {wd})"
        log.printsl(f"{prefix}: {cmd}{suffix}")


class SubcmdShell(SubcmdExec):
    """Wrapper over execution via shell command."""

    def __init__(self) -> None:
        """Execute command as sub shell."""
        SubcmdExec.__init__(self, "sh")
        self.env = os.environ.copy()

    def run(
        self,
        subcmd: str,
        wdir: typing.Optional[Path] = None,
        xenv: typing.Optional[typing.Mapping[str, str]] = None,
    ) -> int:
        with subprocess.Popen(
            subcmd,
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
        self.logcmd("SH", cmd, wdir)
        ret = self.run(cmd, wdir, xenv)
        if ret != 0:
            raise SubcmdError("failed: " + cmd, ret=ret)

    def _mkenv(
        self, xenv: typing.Optional[typing.Mapping[str, str]]
    ) -> dict[str, str]:
        env = copy.copy(self.env)
        if xenv:
            for key, val in xenv.items():
                env[key] = val
        return env


class SubcmdSilofs(SubcmdExec):
    """Wrapper over silofs command-line front-end"""

    def __init__(
        self, use_stdalloc: bool = False, allow_coredump: bool = False
    ) -> None:
        SubcmdExec.__init__(self, "silofs")
        self.use_stdalloc = use_stdalloc
        self.allow_coredump = allow_coredump
        self.giga = 2**30
        self.tera = 2**40

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def init(
        self,
        repodir: Path,
        sup_groups: bool = False,
        allow_root: bool = False,
    ) -> None:
        args = ["init", repodir]
        if sup_groups:
            args = args + ["--sup-groups"]
        if allow_root:
            args = args + ["--allow-root"]
        self.execute_sub(args)

    # pylint: disable=R0913
    def mkfs(
        self,
        repodir_name: Path,
        size: int,
        password: str,
    ) -> None:
        args = ["mkfs", repodir_name]
        srep = self._mkfssize(size)
        args = args + [f"--size={srep}"]
        if password:
            args = args + [f"--password={password}"]
        self.execute_sub(args)

    def _mkfssize(self, size: int) -> str:
        rep = str(size)
        if (size >= self.tera) and (size % self.tera) == 0:
            tsize = int(size / self.tera)
            rep = f"{tsize}T"
        elif (size >= self.giga) and (size % self.giga) == 0:
            gsize = int(size / self.giga)
            rep = f"{gsize}G"
        return rep

    # pylint: disable=R0917
    def mount(
        self,
        repodir_name: Path,
        mntpoint: Path,
        password: str,
        allow_hostids: bool = False,
        allow_xattr_acl: bool = False,
        writeback_cache: bool = False,
        buffer_copy_mode: bool = False,
    ) -> None:
        wb_mode = int(writeback_cache)
        args = ["mount", "--no-prompt", f"--writeback-cache={wb_mode}"]
        if self.allow_coredump:
            args = args + ["--coredump"]
        if self.use_stdalloc:
            args = args + ["--stdalloc"]
        if allow_hostids:
            args = args + ["--allow-hostids"]
        if allow_xattr_acl:
            args = args + ["--allow-xattr-acl"]
        if buffer_copy_mode:
            args = args + ["--buffer-copy-mode"]
        args = args + [str(repodir_name), str(mntpoint)]
        self.execute_run(args, indat=password)

    def umount(self, mntpoint: Path) -> None:
        self.execute_run(["umount", mntpoint])

    def lsmnt(self) -> typing.Iterable[Path]:
        mnts = self.execute_sub(["lsmnt"])
        return [Path(mnt) for mnt in mnts.splitlines()]

    def show_version(self, pathname: Path) -> str:
        return self.execute_sub(["show", "version", pathname])

    def show_repo(self, pathname: Path) -> Path:
        return Path(self.execute_sub(["show", "repo", pathname]))

    def show_boot(self, pathname: Path) -> typing.Tuple[str, str, UUID]:
        boot_info = self.execute_sub(["show", "boot", pathname]).split()
        boot_name = boot_info[0]
        boot_addr = boot_info[1]
        fs_uuid = UUID(boot_info[2])
        return (boot_name, boot_addr, fs_uuid)

    def show_proc(self, pathname: Path) -> str:
        return self.execute_sub(["show", "proc", pathname])

    def show_spstats(self, pathname: Path) -> str:
        return self.execute_sub(["show", "spstats", pathname])

    def show_statx(self, pathname: Path) -> str:
        return self.execute_sub(["show", "statx", pathname])

    def snap(self, name: str, pathname: Path, password: str) -> None:
        args = ["snap", "--no-prompt", "-n", name, pathname]
        self.execute_sub(args, indat=password)

    def snap_offline(
        self, name: str, repodir_name: Path, password: str
    ) -> None:
        args = ["snap", "--no-prompt", "-n", name, "--offline", repodir_name]
        self.execute_sub(args, indat=password)

    def tune(self, pathname: Path, ftype: int) -> None:
        self.execute_run(["tune", "--ftype", str(ftype), pathname])

    def rmfs(self, repodir_name: Path, password: str) -> None:
        args = ["rmfs", "--no-prompt", repodir_name]
        self.execute_run(args, indat=password)

    def fsck(self, repodir_name: Path, password: str) -> None:
        args = ["fsck", "--no-prompt", repodir_name]
        self.execute_sub(args, indat=password)

    def view(self, repodir_name: Path, password: str) -> typing.Iterable[str]:
        args = ["view", "--no-prompt", repodir_name]
        return self.execute_sub(args, indat=password).split("\n")

    def archive(self, repodir_name: Path, arname: str, password: str) -> None:
        args = ["archive", "--no-prompt", repodir_name, "--into", arname]
        self.execute_sub(args, indat=password, timeout=600.0)

    def restore(self, repodir_name: Path, name: str, password: str) -> None:
        args = ["restore", "--no-prompt", repodir_name, "--from", name]
        self.execute_sub(args, indat=password, timeout=600.0)


class SubcmdUnitests(SubcmdExec):
    """Wrapper over silofs-unitests command-line front-end"""

    def __init__(self) -> None:
        SubcmdExec.__init__(self, "silofs-unitests")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def run(self, basedir: Path, level: int = 1, malloc: bool = False) -> None:
        args = [str(basedir)]
        if level > 0:
            args.append(f"--level={level}")
        if malloc:
            args.append("--malloc")
        self.execute_sub(args, timeout=1200)


class SubcmdFuntests(SubcmdExec):
    """Wrapper over silofs-funtests command-line front-end"""

    def __init__(self) -> None:
        SubcmdExec.__init__(self, "silofs-funtests")

    def version(self) -> str:
        return self.execute_sub(["-v"])

    def run(
        self,
        basedir: Path,
        rand: bool = False,
        nostatvfs: bool = False,
        noflaky: bool = False,
    ) -> None:
        args = [str(basedir)]
        if rand:
            args.append("--random")
        if nostatvfs:
            args.append("--nostatvfs")
        if noflaky:
            args.append("--noflaky")
        self.execute_sub(args, wdir=Path("/"), timeout=2400)


class SubcmdGit(SubcmdExec):
    """Wrapper over git command-line utility"""

    def __init__(self) -> None:
        SubcmdExec.__init__(self, "git")

    def version(self) -> str:
        return self.execute_sub(["version"])

    def clone(self, repo: str, dpath: Path, branch: str = "") -> int:
        ret = 0
        args = ["clone", repo, dpath]
        if branch:
            args.append(f"--branch={branch}")
        try:
            self.execute_sub(args, timeout=300)
        except SubcmdError as ex:
            ret = ex.retcode
        return ret


# pylint: disable=R0903
class Subcmds:
    """All command-line wrappers in single class"""

    def __init__(
        self, use_stdalloc: bool = False, allow_coredump: bool = False
    ) -> None:
        self.sh = SubcmdShell()
        self.silofs = SubcmdSilofs(use_stdalloc, allow_coredump)
        self.unitests = SubcmdUnitests()
        self.funtests = SubcmdFuntests()
        self.git = SubcmdGit()
