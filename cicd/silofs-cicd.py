# SPDX-License-Identifier: GPL-3.0
# Run minimal CI/CD pipeline over silofs' code
import functools
import inspect
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, TypeVar

_F = TypeVar("_F", bound=Callable[..., None])


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")


@dataclass
class _Ctx:
    workdir: Path
    archive_file: Path
    citests_dir: Path
    filename: Path = Path(__file__)
    lineno: int = 0
    timestamp: str = _timestamp()


def _with_location(fn: _F) -> _F:
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):  # type: ignore[misc]
        ctx = args[0]
        if isinstance(ctx, _Ctx):
            frame = inspect.stack()[1]
            ctx2 = _Ctx(
                workdir=ctx.workdir,
                archive_file=ctx.archive_file,
                citests_dir=ctx.citests_dir,
                filename=Path(frame.filename),
                lineno=frame.lineno,
                timestamp=_timestamp(),
            )
            args = (ctx2,) + args[1:]
        return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _msgprefix(ctx: _Ctx) -> str:
    """Common messages prefix."""
    pre = ""
    if ctx.timestamp:
        pre = f"[{ctx.timestamp}] "
    if ctx.filename:
        pre = pre + str(ctx.filename.name)
        if ctx.lineno > 0:
            pre = pre + ":" + str(ctx.lineno)
    return pre


@_with_location
def _msg(ctx: _Ctx, txt: str, err: bool = False) -> None:
    """Print a message with context prefix."""
    if err:
        print(f"{_msgprefix(ctx)}: {txt}", file=sys.stderr)
    else:
        print(f"{_msgprefix(ctx)}: {txt}")


@_with_location
def _sep(ctx: _Ctx) -> None:
    """Print separator between sub jobs."""
    txt = "# " * 40
    print(f"{_msgprefix(ctx)}: {txt}")


def _die(ctx: _Ctx, txt: str, out: str = "", err: str = "") -> None:
    """Print optional output of sub-process + error message and exit."""
    if err:
        _msg(ctx, f"\n{err}\n", err=True)
    elif out:
        _msg(ctx, f"\n{out}\n", err=False)
    _msg(ctx, f"failure: {txt}", err=True)
    sys.exit(3)


@_with_location
def _run(
    ctx: _Ctx,
    args: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> None:
    """Execute command as sub-process, die upon error"""
    sub_env = os.environ.copy()
    if not cwd:
        cwd = ctx.workdir
    if env:
        sub_env.update(env)
    sub_env["LC_ALL"] = "C"
    sub_env.pop("CDPATH", None)

    cmd = " ".join(args)
    _msg(ctx, cmd)

    res = subprocess.run(
        args, cwd=cwd, env=sub_env, check=False, text=True, capture_output=True
    )
    rc, out, err = res.returncode, res.stdout, res.stderr
    if rc != 0:
        _die(ctx, cmd, out, err)


@_with_location
def _rmrf(ctx: _Ctx, path: Path) -> None:
    """Wrap shutil.rmtree with logging"""
    if path.exists():
        _msg(ctx, f"rmtree: {path}")
        shutil.rmtree(path)


@_with_location
def _copy(ctx: _Ctx, src: Path, dst: Path) -> None:
    """Wrap shutil.copy with logging"""
    _msg(ctx, f"copy: {src} --> {dst}")
    shutil.copy(src, dst)


@_with_location
def _prepare_workdir(ctx: _Ctx) -> None:
    """Clean workdir and unpack archive."""
    _rmrf(ctx, ctx.workdir)
    _copy(ctx, ctx.archive_file, ctx.citests_dir)
    _run(ctx, ["tar", "xfz", ctx.archive_file.name], cwd=ctx.citests_dir)


@_with_location
def _cleanup_workdir(ctx: _Ctx) -> None:
    """Clean workdir from any leftovers."""
    _rmrf(ctx, ctx.workdir)


@_with_location
def _build_from_source(ctx: _Ctx) -> None:
    _msg(ctx, f"build from source: {ctx.archive_file}")
    _prepare_workdir(ctx)

    _msg(ctx, f"check code style: {ctx.workdir}")
    _run(ctx, ["./scripts/checkcodefmt.sh"])

    _msg(ctx, f"check build at: {ctx.workdir}")
    _run(ctx, ["./configure"])
    _run(ctx, ["make"])
    _run(ctx, ["make", "distcheck"])
    _run(ctx, ["make", "clean"])
    _cleanup_workdir(ctx)
    _msg(ctx, f"build from source OK: {ctx.archive_file}")
    _sep(ctx)


@_with_location
def _build_devel_default(ctx: _Ctx) -> None:
    _msg(ctx, "build devel default mode")
    _run(ctx, ["make", "-f", "devel.mk"])
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "build with analyzer")
    _run(ctx, ["make", "-f", "devel.mk", "O=0", "ANALYZER=1"])
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "run unit-tests")
    _run(
        ctx,
        ["make", "-f", "devel.mk", "O=2", "check"],
        env={"SILOFS_PANIC_MODE_WAIT": "1"},
    )
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "build devel default mode OK")
    _sep(ctx)


@_with_location
def _build_devel_clang(ctx: _Ctx) -> None:
    _msg(ctx, "build and check with clang")
    _msg(ctx, "run clang-scan")
    _run(
        ctx,
        ["make", "-f", "devel.mk", "CC=clang", "V=1", "O=2", "scan"],
    )
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "run clang-tidy")
    _run(
        ctx,
        ["make", "-f", "devel.mk", "CC=clang", "O=2", "tidy"],
    )
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "build and check with clang OK")
    _sep(ctx)


@_with_location
def _build_devel_sanitizer(ctx: _Ctx) -> None:
    _msg(ctx, "sanitizer check")
    utests_dir = ctx.workdir / "build" / "test" / "utests"
    lsan_supp_file = ctx.workdir / "test/utests/lsan_suppressions.txt"
    _run(ctx, ["make", "-f", "devel.mk", "O=1", "SANITIZER=1"])
    san_env = {
        "ASAN_OPTIONS": "detect_leaks=1",
        "LSAN_OPTIONS": f"suppressions={lsan_supp_file}",
    }
    _run(
        ctx,
        [
            str(utests_dir / "silofs-utests"),
            str(utests_dir / "ut"),
            "--malloc",
            "--level=1",
            "--silent",
        ],
        env=san_env,
    )
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "sanitizer check OK")
    _sep(ctx)


@_with_location
def _build_devel_valgrind(ctx: _Ctx) -> None:
    _msg(ctx, "valgrind check")
    utests_dir = ctx.workdir / "build" / "test" / "utests"
    _run(ctx, ["make", "-f", "devel.mk"])
    _run(
        ctx,
        [
            "valgrind",
            "--tool=memcheck",
            "--error-exitcode=1",
            str(utests_dir / "silofs-utests"),
            str(utests_dir / "ut"),
            "--malloc",
            "--level=1",
            "--silent",
        ],
    )
    _run(ctx, ["make", "-f", "devel.mk", "reset"])
    _msg(ctx, "valgrind check OK")
    _sep(ctx)


@_with_location
def _build_with_devel_mk(ctx: _Ctx) -> None:
    _msg(ctx, "developer's checks")
    _prepare_workdir(ctx)
    _build_devel_default(ctx)
    _build_devel_clang(ctx)
    _build_devel_sanitizer(ctx)
    _build_devel_valgrind(ctx)
    _cleanup_workdir(ctx)
    _msg(ctx, "developer's checks OK")
    _sep(ctx)


@_with_location
def _run_heapcheck(ctx: _Ctx) -> None:
    tmpdir = ctx.workdir / "build" / "local" / "tmp"
    build_dir = ctx.workdir / "build"
    _msg(ctx, "memory-heap check")
    _prepare_workdir(ctx)
    _run(ctx, ["./bootstrap"])
    tmpdir.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(exist_ok=True)
    configure_prefix = f"--prefix={ctx.workdir}/build/local"
    _run(
        ctx,
        [
            "../configure",
            configure_prefix,
            "--enable-compile-warnings=error",
            "--with-tcmalloc",
        ],
        cwd=build_dir,
    )
    _run(ctx, ["make", "install"], cwd=build_dir)
    heap_env = {
        "HEAPCHECK": "normal",
        "HEAP_CHECK_TEST_POINTER_ALIGNMENT": "1",
    }
    _run(
        ctx,
        [
            str(ctx.workdir / "build/local/bin/silofs-utests"),
            str(ctx.workdir / "build/local/tmp"),
            "--malloc",
            "--level=2",
            "--silent",
        ],
        env=heap_env,
    )
    _cleanup_workdir(ctx)
    _msg(ctx, "memory-heap check OK")
    _sep(ctx)


@_with_location
def _run_dist_package(ctx: _Ctx) -> None:
    _msg(ctx, "packaging")
    _prepare_workdir(ctx)
    _run(ctx, ["./pkg/packagize.sh"])
    _cleanup_workdir(ctx)
    _msg(ctx, "packaging OK")
    _sep(ctx)


@_with_location
def _exec_cicd(ctx: _Ctx) -> None:
    _msg(ctx, f"execute ci/cd: {ctx.archive_file} {ctx.citests_dir}")
    _build_from_source(ctx)
    _build_with_devel_mk(ctx)
    _run_heapcheck(ctx)
    _run_dist_package(ctx)
    _msg(ctx, f"execute ci/cd OK: {ctx.archive_file} {ctx.citests_dir}")


@_with_location
def _prep_cicd(ctx: _Ctx) -> None:
    _msg(ctx, f"prepare: {ctx.archive_file} {ctx.citests_dir}")
    ctx.citests_dir.mkdir(parents=True, exist_ok=True)
    _run(ctx, ["ls", "-l", str(ctx.citests_dir)], cwd=ctx.citests_dir)
    _run(ctx, ["ls", "-l", str(ctx.archive_file)], cwd=ctx.citests_dir)


def _make_context(arfile: Path, citdir: Path) -> _Ctx:
    archive_file = Path(arfile).resolve()
    citests_dir = Path(citdir).resolve()
    dist_name = archive_file.name.replace(".tar.gz", "")
    workdir = citests_dir / dist_name
    return _Ctx(
        workdir=workdir, archive_file=archive_file, citests_dir=citests_dir
    )


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: '{sys.argv[0]} <archive-file> <citests-dir>'")
        sys.exit(1)
    arfile, citdir = Path(sys.argv[1]), Path(sys.argv[2])
    if not arfile.is_file():
        print(f"{sys.argv[0]}: not a file {arfile}")
        sys.exit(2)
    ctx = _make_context(arfile, citdir)
    _prep_cicd(ctx)
    _exec_cicd(ctx)


if __name__ == "__main__":
    main()
