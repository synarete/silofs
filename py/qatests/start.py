# SPDX-License-Identifier: GPL-3.0
import argparse
import sys
import traceback
from pathlib import Path

from . import ctx
from . import run


class ArgsException(Exception):
    def __init__(self, msg: str) -> None:
        Exception.__init__(self, msg)


# pylint: disable=R0902
class ProgInfo:
    def __init__(self) -> None:
        self.version = "0.0.0"
        self.release = "0"
        self.revision = "0"
        self.argv = sys.argv
        self.title = "silofs-qatests"
        self.version_mode = False
        self.testdir = ""
        self.mntdir = ""

    def version_string(self) -> str:
        return f"{self.version}-{self.release}.{self.revision}"

    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.title,
            usage=f"{self.title} test-dir mount-point",
            description="Run QA-test for silofs file-system",
            epilog="",
        )
        parser.add_argument(
            "test-dir",
            help="Local (empty) directory",
            nargs="?",
            default="",
        )
        parser.add_argument(
            "mount-point",
            help="Testing mount-point directory",
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
        args = parser.parse_args(self.argv[1:])
        argsd = args.__dict__
        self.version_mode = args.version
        self.testdir = argsd["test-dir"]
        self.mntdir = argsd["mount-point"]

    def check_args(self) -> None:
        if self.version_mode:
            return
        if not self.testdir:
            raise ArgsException("missing test-dir")
        if not self.mntdir:
            raise ArgsException("missing mount-point")
        test_dir = Path(self.testdir)
        if not test_dir.is_dir():
            raise ArgsException(f"not a directory: {test_dir}")
        mount_point = Path(self.mntdir)
        if not mount_point.is_dir():
            raise ArgsException(f"not a directory: {mount_point}")

    def update_proc_title(self) -> None:
        try:
            # pylint: disable=C0415
            from setproctitle import setproctitle  # type: ignore

            setproctitle(self.title)
        except ImportError:
            pass

    def start_run(self) -> None:
        if self.version_mode:
            print(self.version_string())
        else:
            run.run_tests(self._make_test_config())

    def _make_test_config(self) -> ctx.TestConfig:
        return run.make_config(Path(self.testdir), Path(self.mntdir))


def run_silofs_qatests(prog_info: ProgInfo = ProgInfo()) -> None:
    try:
        prog_info.update_proc_title()
        prog_info.parse_args()
        prog_info.check_args()
        prog_info.start_run()
    except ArgsException as aex:
        print(f"{prog_info.title}: {aex}")
        sys.exit(1)
    except Exception as ex:
        print(f"{prog_info.title}: {ex}")
        traceback.print_exc()
        sys.exit(2)
