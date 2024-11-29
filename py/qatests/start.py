# SPDX-License-Identifier: GPL-3.0
import argparse
import sys
import traceback
from pathlib import Path

from . import run
from . import utils
from .cmd import CmdError
from .expect import ExpectException


class ArgsException(Exception):
    def __init__(self, msg: str) -> None:
        Exception.__init__(self, msg)


class ProgArgs(run.RunArgs):
    def __init__(self) -> None:
        super().__init__()
        self.argv = sys.argv

    def check_config(self) -> None:
        basedir = self.config.basedir
        if not utils.is_empty_dir(basedir):
            raise ArgsException(f"not an empty directory: {basedir}")
        mntdir = self.config.mntdir
        if not utils.is_dir(mntdir):
            raise ArgsException(f"illegal mount-point: {mntdir}")
        if not utils.is_empty_dir(mntdir):
            raise ArgsException(f"not an empty mount-point: {mntdir}")


# pylint: disable=R0902
class ProgInfo:
    def __init__(self) -> None:
        self.version = "0.0.0"
        self.release = "0"
        self.revision = "0"
        self.title = "silofs-qatests"
        self.version_mode = False
        self.config = ""
        self.basedir = ""
        self.mntdir = ""
        self.args = ProgArgs()

    def version_string(self) -> str:
        return f"{self.version}-{self.release}.{self.revision}"

    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.title,
            usage=f"{self.title} [-c config] basedir mntdir",
            description="Run QA-test for silofs file-system",
            epilog="",
        )
        parser.add_argument(
            "basedir",
            help="Tests base directory",
            nargs="?",
            default="",
        )
        parser.add_argument(
            "mntdir",
            help="Mount directory",
            nargs="?",
            default="",
        )
        parser.add_argument(
            "-c",
            "--config",
            help="TOML configuration file",
        )
        parser.add_argument(
            "-v",
            "--version",
            help="Show version info",
            action="store_true",
            default=False,
            required=False,
        )
        args = parser.parse_args(self.args.argv[1:])
        self.version_mode = args.version
        self.config = args.config
        self.basedir = args.basedir
        self.mntdir = args.mntdir

    def check_args(self) -> None:
        if not self.basedir:
            raise ArgsException("missing basedir")
        if not self.mntdir:
            raise ArgsException("missing mntdir")

    def update_config(self) -> None:
        if self.config:
            self.args.load_config(Path(self.config).resolve(strict=True))
        self.args.config.basedir = Path(self.basedir).resolve(strict=True)
        self.args.config.mntdir = Path(self.mntdir).resolve(strict=True)
        self.args.check_config()

    def update_proc_title(self) -> None:
        try:
            # pylint: disable=C0415
            from setproctitle import setproctitle  # type: ignore

            setproctitle(self.title)
        except ImportError:
            pass

    def start_run(self) -> None:
        run.run_tests(self.args)


def run_silofs_qatests(prog_info: ProgInfo = ProgInfo()) -> None:
    try:
        prog_info.update_proc_title()
        prog_info.parse_args()
        if prog_info.version_mode:
            print(prog_info.version_string())
        else:
            prog_info.check_args()
            prog_info.update_config()
            prog_info.start_run()
    except ArgsException as aex:
        print(f"{prog_info.title}: args error: {aex}")
        sys.exit(1)
    except CmdError as cer:
        print(f"{prog_info.title}: cmd error: {cer}")
        sys.exit(2)
    except ExpectException as eer:
        print(f"{prog_info.title}: expect error: {eer}")
        sys.exit(3)
    except (OSError, RuntimeError) as err:
        print(f"{prog_info.title}: {err}")
        traceback.print_exc()
        sys.exit(4)
