# SPDX-License-Identifier: GPL-3.0
import argparse
import sys
import traceback
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
            usage=f"{self.title} [--restore] repodir/name archivedir",
            description="Archive or restore silofs file-system",
            epilog="",
        )
        parser.add_argument(
            "repodir/name",
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
        argsd = args.__dict__
        self.version_mode = args.version
        self.restore_mode = args.restore
        self.repodir_name = argsd["repodir/name"]
        self.archive_dir = args.archivedir
        self.password = args.password

    def check_args(self) -> None:
        if self.version_mode:
            return
        if not self.repodir_name:
            raise ArchiveException("missing repodir/name")
        if not self.archive_dir:
            raise ArchiveException("missing archive-dir")
        repodir_name = Path(self.repodir_name)
        if self.restore_mode:
            if repodir_name.exists():
                raise ArchiveException(f"already exists: {repodir_name}")
        else:
            if not repodir_name.is_file():
                raise ArchiveException(f"not a regular file: {repodir_name}")
        archive_dir = Path(self.archive_dir)
        if not archive_dir.is_dir():
            raise ArchiveException(f"not a directory: {archive_dir}")

    def make_archive_ctx(self) -> ArchiveCtx:
        return ArchiveCtx(
            Path(self.repodir_name),
            Path(self.archive_dir),
            self.password,
            self.restore_mode,
        )

    def update_proc_title(self) -> None:
        try:
            # pylint: disable=C0415
            from setproctitle import setproctitle  # type: ignore

            setproctitle(self.title)
        except ImportError:
            pass


def _show_version(prog_info: ProgInfo) -> None:
    print(prog_info.version_string())


def _exec_archive(prog_info: ProgInfo) -> None:
    archive_ctx = prog_info.make_archive_ctx()
    archive_ctx.execute_archive()


def run_silofs_archive(prog_info: ProgInfo = ProgInfo()) -> None:
    prog_info.update_proc_title()
    try:
        prog_info.parse_args()
        prog_info.check_args()
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
