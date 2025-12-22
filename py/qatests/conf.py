# SPDX-License-Identifier: GPL-3.0
import json
import tomllib  # noqa
from pathlib import Path  # noqa
from typing import Dict, Optional

import pydantic


_DEFAULT_REPO_URL = "@default"
_POSTGRESQL_REPO_URL = "https://git.postgresql.org/git/postgresql.git"
_RSYNC_REPO_URL = "git://git.samba.org/rsync.git"
_FINDUTILS_REPO_URL = "https://git.savannah.gnu.org/git/findutils.git"
_GITSCM_REPO_URL = "https://github.com/git/git.git"
_CPYTHON_REPO_URL = "https://github.com/python/cpython.git"
_SILOFS_REPO_URL = "https://github.com/synarete/silofs"


class ConfException(Exception):
    def __init__(self, msg: str) -> None:
        Exception.__init__(self, msg)


class ConfigParams(pydantic.BaseModel):
    password: str = "0123456789abcdef"
    use_stdalloc: bool = False
    allow_coredump: bool = False


class ConfigRemotes(pydantic.BaseModel):
    postgresql_repo_url: str = ""
    rsync_repo_url: str = ""
    findutils_repo_url: str = ""
    git_repo_url: str = ""
    cpython_repo_url: str = ""
    silofs_repo_url: str = ""


class Config(pydantic.BaseModel):
    basedir: Path = Path(".").resolve(strict=True)
    mntdir: Path = Path(".").resolve(strict=True)
    params: ConfigParams = ConfigParams()
    remotes: ConfigRemotes = ConfigRemotes()


class MetaJRef(pydantic.BaseModel):
    version: str = ""
    fmtvers: int = 0
    btype: str = ""
    mode: str = ""
    mbref: str = ""


class FsIds(pydantic.BaseModel):
    users: Optional[Dict[str, int]] = {}
    groups: Optional[Dict[str, int]] = {}


def _load_toml_as_json(path: Path) -> str:
    with open(path, "rb") as f:
        toml_data = tomllib.load(f)
        return json.dumps(toml_data)


def _load_config(path: Path) -> Config:
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return Config(**json_conf)
    except tomllib.TOMLDecodeError as tde:
        raise ConfException(f"bad configuration toml: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ConfException(f"non-valid configuration: {path}") from ve


def _use_default_url(url: str) -> bool:
    return url.strip() == _DEFAULT_REPO_URL


def _fixup_remotes(remotes: ConfigRemotes) -> ConfigRemotes:
    if _use_default_url(remotes.postgresql_repo_url):
        remotes.postgresql_repo_url = _POSTGRESQL_REPO_URL
    if _use_default_url(remotes.rsync_repo_url):
        remotes.rsync_repo_url = _RSYNC_REPO_URL
    if _use_default_url(remotes.findutils_repo_url):
        remotes.findutils_repo_url = _FINDUTILS_REPO_URL
    if _use_default_url(remotes.git_repo_url):
        remotes.git_repo_url = _GITSCM_REPO_URL
    if _use_default_url(remotes.cpython_repo_url):
        remotes.cpython_repo_url = _CPYTHON_REPO_URL
    if _use_default_url(remotes.silofs_repo_url):
        remotes.silofs_repo_url = _SILOFS_REPO_URL
    return remotes


def load_config(path: Path) -> Config:
    config = _load_config(path)
    config.remotes = _fixup_remotes(config.remotes)
    return config


def load_fsids(repodir: Path) -> FsIds:
    path = repodir / "fsids.conf"
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return FsIds(**json_conf)
    except tomllib.TOMLDecodeError as tde:
        raise ConfException(f"bad fs-ids conf: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ConfException(f"non-valid fs-ids conf: {path}") from ve


def _verify_meta_jref(meta_jref: MetaJRef) -> MetaJRef:
    if not meta_jref.version:
        raise ConfException(f"non-valid meta-jref version: {meta_jref}")
    if meta_jref.fmtvers != 1:
        raise ConfException(f"non-valid meta-jref fmtvers: {meta_jref}")
    if meta_jref.mode not in ("filesystem", "archive"):
        raise ConfException(f"non-valid meta-jref mode: {meta_jref}")
    if len(meta_jref.mbref) != 64:
        raise ConfException(f"non-valid meta-jref mbref: {meta_jref}")
    return meta_jref


def load_meta_jref(path: Path) -> MetaJRef:
    """Load and verify meta-ref json file into internal representation."""
    with open(path, "rb") as f:
        json_conf = json.load(f)
    try:
        return _verify_meta_jref(MetaJRef(**json_conf))
    except pydantic.ValidationError as ve:
        raise ConfException(f"non-valid metaref at: {path}") from ve
