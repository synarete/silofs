# SPDX-License-Identifier: GPL-3.0
import json
from pathlib import Path
from typing import Dict, Optional

import pydantic

import toml

from .expect import ExpectException

_POSTGRESQL_REPO_URL = "https://git.postgresql.org/git/postgresql.git"
_RSYNC_REPO_URL = "git://git.samba.org/rsync.git"
_FINDUTILS_REPO_URL = "https://git.savannah.gnu.org/git/findutils.git"
_GITSCM_REPO_URL = "https://github.com/git/git.git"
_SILOFS_REPO_URL = "https://github.com/synarete/silofs"
_CENTOS_MIRROR_URL = "https://mirrors.centos.org"


class ConfigParams(pydantic.BaseModel):
    password: str = "123456"
    use_stdalloc: bool = False
    allow_coredump: bool = False


class ConfigRemotes(pydantic.BaseModel):
    postgresql_repo_url: str = _POSTGRESQL_REPO_URL
    rsync_repo_url: str = _RSYNC_REPO_URL
    findutils_repo_url: str = _FINDUTILS_REPO_URL
    git_repo_url: str = _GITSCM_REPO_URL
    silofs_repo_url: str = _SILOFS_REPO_URL
    centos_mirror_url: str = _CENTOS_MIRROR_URL


class Config(pydantic.BaseModel):
    basedir: Path = Path(".").resolve(strict=True)
    mntdir: Path = Path(".").resolve(strict=True)
    params: ConfigParams = ConfigParams()
    remotes: ConfigRemotes = ConfigRemotes()


class FsBootRef(pydantic.BaseModel):
    bref: str = pydantic.Field(str, min_length=64, max_length=128)


class FsIdsConf(pydantic.BaseModel):
    users: Optional[Dict[str, int]] = {}
    groups: Optional[Dict[str, int]] = {}


def _load_toml_as_json(path: Path) -> str:
    toml_data = toml.load(path)
    return json.dumps(toml_data)


def load_config(path: Path) -> Config:
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return Config(**json_conf)
    except toml.TomlDecodeError as tde:
        raise ExpectException(f"bad configuration toml: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ExpectException(f"non-valid configuration: {path}") from ve


def load_fsids(repodir: Path) -> FsIdsConf:
    path = repodir / "fsids.conf"
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return FsIdsConf(**json_conf)
    except toml.TomlDecodeError as tde:
        raise ExpectException(f"bad fs-ids conf: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ExpectException(f"non-valid fs-ids conf: {path}") from ve


def load_bref(path: Path) -> FsBootRef:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if len(lines) != 1:
        raise ExpectException(f"bad fs boot-ref: {path}")
    dat = str(lines[0]).strip()
    if not dat.isascii():
        raise ExpectException(f"non-ascii fs boot-ref: {path}")
    try:
        bref = FsBootRef(bref=dat)
    except pydantic.ValidationError as ve:
        raise ExpectException(f"non-valid fs boot-ref: {path}") from ve
    return bref
