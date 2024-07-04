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


class Config(pydantic.BaseModel):
    basedir: Path = Path(".").resolve(strict=True)
    mntdir: Path = Path(".").resolve(strict=True)
    params: ConfigParams = ConfigParams()
    remotes: ConfigRemotes = ConfigRemotes()


class FsBootConfRefs(pydantic.BaseModel):
    boot: Optional[str] = pydantic.Field(None, max_length=64)
    pack: Optional[str] = pydantic.Field(None, max_length=64)


class FsBootConf(pydantic.BaseModel):
    refs: FsBootConfRefs = FsBootConfRefs()
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


def load_fs_boot_conf(path: Path) -> FsBootConf:
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return FsBootConf(**json_conf)
    except toml.TomlDecodeError as tde:
        raise ExpectException(f"bad fs boot-conf toml: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ExpectException(f"non-valid fs boot-conf: {path}") from ve
