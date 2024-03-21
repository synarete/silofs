# SPDX-License-Identifier: GPL-3.0
import getpass
import json
import tempfile
import typing
from pathlib import Path

import pydantic

import toml

from .blobs import BlobData
from .model import FsConf, FsRefID
from .subcmd import SilofsCmd
from .utils import ArchiveException


# pylint: disable=R0903
class FsView:
    def __init__(self, repodir_name: Path, ids: typing.Iterable[str]) -> None:
        self.repodir_name = repodir_name
        valid_ids = [rid.strip() for rid in ids if len(rid.strip()) > 0]
        self.view = [FsRefID(rid=rid) for rid in valid_ids]

    def __len__(self) -> int:
        return len(self.view)


class FsMeta:
    def __init__(self, pathname: Path) -> None:
        self.repodir_name = pathname.absolute()
        self.repodir = self.repodir_name.parents[0]
        self.name = self.repodir_name.name
        self.conf = FsConf()

    def load_conf(self) -> None:
        conf_path = self.repodir_name
        try:
            toml_data = toml.load(conf_path)
            json_data = json.dumps(toml_data)
            json_conf = json.loads(json_data)
            self.conf = FsConf(**json_conf)
        except toml.TomlDecodeError as tde:
            raise ArchiveException(f"bad fs-conf toml: {conf_path}") from tde
        except pydantic.ValidationError as ve:
            raise ArchiveException(f"non-valid fs-conf: {conf_path}") from ve


class LocalCtx:
    def __init__(self, repodir_name: Path, passwd: str = "") -> None:
        self.repodir_name = repodir_name
        self.passwd = passwd
        self.meta = FsMeta(repodir_name)
        self.silofs_cmd = SilofsCmd()

    def check_args(self) -> None:
        self.check_meta()
        self.check_cmd()

    def check_meta(self) -> None:
        if not self.meta.repodir.is_dir():
            raise ArchiveException(f"not a directory: {self.meta.repodir}")
        if not self.meta.repodir_name.exists():
            raise ArchiveException(f"not-exists: {self.meta.repodir_name}")
        if not self.meta.repodir_name.is_file():
            raise ArchiveException(f"not a file: {self.meta.repodir_name}")

    def check_cmd(self) -> None:
        version = self.silofs_cmd.exec_version()
        if not version:
            raise ArchiveException(f"bad silofs: {self.silofs_cmd.xbin}")

    def load_meta(self) -> None:
        self.meta.load_conf()

    def require_passwd(self) -> None:
        if not self.passwd:
            self.passwd = getpass.getpass()

    def fetch_view(self) -> FsView:
        repodir_name, passwd = self.meta.repodir_name, self.passwd
        ids = self.silofs_cmd.exec_view(repodir_name, passwd)
        return FsView(repodir_name, ids)

    def fetch_ref(self, refid: FsRefID) -> BlobData:
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as tmpf:
            outfile = Path(tmpf.name)
            self.silofs_cmd.exec_export(self.meta.repodir, refid.rid, outfile)
            lines = tmpf.readlines() + [""]
            ascii_data = str(lines[0])
            return BlobData.from_base64(ascii_data)
