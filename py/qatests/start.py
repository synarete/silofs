# SPDX-License-Identifier: GPL-3.0
import argparse
import sys
import traceback
from pathlib import Path

from . import conf
from . import run
from . import utils


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
        self.configfile = ""
        self.config = conf.TestConfig()

    def version_string(self) -> str:
        return f"{self.version}-{self.release}.{self.revision}"

    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.title,
            usage=f"{self.title} config-file",
            description="Run QA-test for silofs file-system",
            epilog="",
        )
        parser.add_argument(
            "config-file",
            help="Tests toml configuration file",
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
        self.configfile = argsd["config-file"]

    def update_proc_title(self) -> None:
        try:
            # pylint: disable=C0415
            from setproctitle import setproctitle  # type: ignore

            setproctitle(self.title)
        except ImportError:
            pass

    def load_config(self) -> None:
        if not self.configfile:
            raise ArgsException("missing config-file")
        path = Path(self.configfile).resolve(strict=True)
        self.config = conf.load_config(path)

    def check_config(self) -> None:
        basedir = self.config.basedir
        if not utils.is_empty_dir(basedir):
            raise ArgsException(f"not an empty directory: {basedir}")
        mntdir = self.config.mntdir
        if not utils.is_dir(mntdir):
            raise ArgsException(f"illegal mount-point: {mntdir}")
        if not utils.is_empty_dir(mntdir):
            raise ArgsException(f"not an empty mount-point: {mntdir}")

    def start_run(self) -> None:
        run.run_tests(self.config)


def run_silofs_qatests(prog_info: ProgInfo = ProgInfo()) -> None:
    try:
        prog_info.update_proc_title()
        prog_info.parse_args()
        if prog_info.version_mode:
            print(prog_info.version_string())
        else:
            prog_info.load_config()
            prog_info.check_config()
            prog_info.start_run()
    except ArgsException as aex:
        print(f"{prog_info.title}: {aex}")
        sys.exit(1)
    except Exception as ex:
        print(f"{prog_info.title}: {ex}")
        traceback.print_exc()
        sys.exit(2)
