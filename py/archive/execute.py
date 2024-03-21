# SPDX-License-Identifier: GPL-3.0
import argparse
import sys
import traceback
import typing
from pathlib import Path

from .archive import ArchiveCtx
from .utils import ArchiveException


# pylint: disable=R0902
class ProgInfo:
    def __init__(self) -> None:
        self.version = "0.0.0"
        self.release = "0"
        self.revision = "0"
        self.argv = sys.argv
        self.title = "silofs-archive"
        self.version_mode = False
        self.restore_mode = False
        self.repodir_name = ""
        self.archive_dir = ""
        self.password = ""

    def version_string(self) -> str:
        return f"{self.version}-{self.release}.{self.revision}"

    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.title,
            usage=f"{self.title} [--restore] fspathname archivedir",
            description="Archive or restore silofs file-system",
            epilog="",
        )
        parser.add_argument(
            "fspathname",
            help="File-system meta-file within local repository",
            nargs="?",
            default="",
        )
        parser.add_argument(
            "archivedir",
            help="Archive objects directory",
            nargs="?",
            default="",
        )
        parser.add_argument(
            "-v",
            "--version",
            help="Show version info",
            action="store_true",
            default=False,
            required=False,
        )
        parser.add_argument(
            "-R",
            "--restore",
            help="Restore file-system from objects archive",
            action="store_true",
            default=False,
            required=False,
        )
        parser.add_argument(
            "-P",
            "--password",
            help="Password of local file-system (debug mode only)",
            default="",
            required=False,
        )
        args = parser.parse_args(self.argv[1:])
        self.version_mode = args.version
        self.restore_mode = args.restore
        self.repodir_name = args.fspathname
        self.archive_dir = args.archivedir
        self.password = args.password


def _update_proc_title(prog_info: ProgInfo) -> None:
    try:
        # pylint: disable=C0415
        from setproctitle import setproctitle  # type: ignore

        setproctitle(prog_info.title)
    except ImportError:
        pass


def _show_version(prog_info: ProgInfo) -> typing.NoReturn:
    print(prog_info.version_string())
    sys.exit(0)


def _exec_archive(prog_info: ProgInfo) -> None:
    if not prog_info.repodir_name:
        raise ArchiveException("missing fspathname")
    repodir_name = Path(prog_info.repodir_name)
    if len(repodir_name.name) == 0 or len(repodir_name.parents) == 0:
        raise ArchiveException(f"illegal fspathname: {repodir_name}")
    archive_dir = Path(prog_info.archive_dir)
    if len(archive_dir.name) == 0:
        raise ArchiveException(f"illegal archivedir: {archive_dir}")
    archive_ctx = ArchiveCtx(repodir_name, archive_dir, prog_info.password)
    archive_ctx.execute_archive()


def run_silofs_archive(prog_info: ProgInfo = ProgInfo()) -> None:
    _update_proc_title(prog_info)
    try:
        prog_info.parse_args()
        if prog_info.version_mode:
            _show_version(prog_info)
        elif prog_info.restore_mode:
            pass
        else:
            _exec_archive(prog_info)
    except ArchiveException as aex:
        print(f"{prog_info.title}: {aex}")
        sys.exit(1)
    except Exception as exp:
        print(f"{prog_info.title}: {exp}")
        traceback.print_exc()
        sys.exit(2)
