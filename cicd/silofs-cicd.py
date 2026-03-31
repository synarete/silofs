# SPDX-License-Identifier: GPL-3.0
# Run minimal CI/CD pipeline over silofs' code
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class _Ctx:
    workdir: Path
    archive_file: Path
    citests_dir: Path
    timestamp: bool = False


def _timestamp() -> str:
    ts_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
    return f"[{ts_now}]"


def _msgprefix(ctx: _Ctx) -> str:
    """Script name as messages prefix."""
    pre = str(Path(__file__).name)
    if ctx.timestamp:
        pre = _timestamp() + " " + pre
    return pre


def _msg(ctx: _Ctx, txt: str, err: bool = False) -> None:
    """Print a message to stdout."""
    if err:
        print(f"{_msgprefix(ctx)}: {txt}", file=sys.stderr)
    else:
        print(f"{_msgprefix(ctx)}: {txt}")


def _sep(ctx: _Ctx, txt: str) -> None:
    """Print a message followed by a separator."""
    _msg(ctx, txt)
    _msg(ctx, "# " * 32)


def _die(ctx: _Ctx, txt: str, out: str = "", err: str = "") -> None:
    """Print optional output of sub-process + error message and exit."""
    if err:
        _msg(ctx, f"{err}", err=True)
    elif out:
        _msg(ctx, f"{out}", err=False)
    _msg(ctx, f"failure: {txt}", err=True)
    sys.exit(2)


def _runcmd(
    args: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """Execute command as sub-process."""
    sub_env = os.environ.copy()
    if env:
        sub_env.update(env)
    sub_env["LC_ALL"] = "C"
    sub_env.pop("CDPATH", None)
    res = subprocess.run(
        args, cwd=cwd, env=sub_env, check=True, text=True, capture_output=True
    )
    return (res.returncode, res.stdout, res.stderr)


def _workdir(ctx: _Ctx, cwd: Optional[Path] = None) -> Path:
    wd = cwd
    if wd is None:
        wd = ctx.workdir
    return wd


def _run(
    ctx: _Ctx,
    args: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> None:
    """Execute command as sub-process, die upon error"""
    cmd = " ".join(args)
    _msg(ctx, cmd)
    rc, out, err = _runcmd(args, _workdir(ctx, cwd), env)
    if rc != 0:
        _die(ctx, cmd, out, err)


def _rmrf(ctx: _Ctx, path: Path) -> None:
    """Wrap shutil.rmtree with logging"""
    if path.exists():
        _msg(ctx, f"rmtree: {path}")
        shutil.rmtree(path)


def _copy(ctx: _Ctx, src: Path, dst: Path) -> None:
    """Wrap shutil.copy with logging"""
    _msg(ctx, f"copy: {src} --> {dst}")
    shutil.copy(src, dst)


def _prepare_workdir(ctx: _Ctx) -> None:
    """Clean workdir and unpack archive."""
    _rmrf(ctx, ctx.workdir)
    _copy(ctx, ctx.archive_file, ctx.citests_dir)
    _run(ctx, ["tar", "xfz", ctx.archive_file.name], cwd=ctx.citests_dir)


def _cleanup_workdir(ctx: _Ctx) -> None:
    """Clean workdir from any leftovers."""
    _rmrf(ctx, ctx.workdir)


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
    _sep(ctx, f"build from source OK: {ctx.archive_file}")


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
    _sep(ctx, "build devel default mode OK")


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
    _sep(ctx, "build and check with clang OK")


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
    _sep(ctx, "sanitizer check OK")


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
    _sep(ctx, "valgrind check OK")


def _build_with_devel_mk(ctx: _Ctx) -> None:
    _msg(ctx, "developer's checks")
    _prepare_workdir(ctx)
    _build_devel_default(ctx)
    _build_devel_clang(ctx)
    _build_devel_sanitizer(ctx)
    _build_devel_valgrind(ctx)
    _cleanup_workdir(ctx)
    _sep(ctx, "developer's checks OK")


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
    _sep(ctx, "memory-heap check OK")


def _run_dist_package(ctx: _Ctx) -> None:
    _msg(ctx, "dist-package")
    _prepare_workdir(ctx)
    _run(ctx, ["./dist/packagize.sh"])
    _cleanup_workdir(ctx)
    _sep(ctx, "dist-package OK")


def _exec_cicd(ctx: _Ctx) -> None:
    _msg(ctx, f"execute ci/cd: {ctx.archive_file} {ctx.citests_dir}")
    _build_from_source(ctx)
    _build_with_devel_mk(ctx)
    _run_heapcheck(ctx)
    _run_dist_package(ctx)
    _msg(ctx, f"execute ci/cd OK: {ctx.archive_file} {ctx.citests_dir}")


def _prep_cicd(ctx: _Ctx) -> None:
    _msg(ctx, f"prepare: {ctx.archive_file} {ctx.citests_dir}")
    if not ctx.archive_file.is_file():
        _die(ctx, f"archive file not found: {ctx.archive_file}")
    ctx.citests_dir.mkdir(parents=True, exist_ok=True)
    _run(ctx, ["ls", "-l", str(ctx.citests_dir)], cwd=ctx.citests_dir)


def _make_context(arfile, citdir) -> _Ctx:
    archive_file = Path(arfile).resolve()
    citests_dir = Path(citdir).resolve()
    dist_name = archive_file.name.replace(".tar.gz", "")
    workdir = citests_dir / dist_name
    timestamp = os.environ.get("SILOFS_TIMESTAMP", "0") == "1"
    return _Ctx(
        workdir=workdir,
        archive_file=archive_file,
        citests_dir=citests_dir,
        timestamp=timestamp,
    )


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: '{sys.argv[0]} <archive-file> <citests-dir>'")
        sys.exit(1)
    arfile, citdir = sys.argv[1], sys.argv[2]
    ctx = _make_context(arfile, citdir)
    _prep_cicd(ctx)
    _exec_cicd(ctx)


if __name__ == "__main__":
    main()
