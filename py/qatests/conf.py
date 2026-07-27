# SPDX-License-Identifier: GPL-3.0
import json
import tomllib  # noqa
from pathlib import Path  # noqa

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


class FsMeta(pydantic.BaseModel):
    version: str = ""
    fmtvers: int = 0
    timestamp: str = ""


class FsRef(pydantic.BaseModel):
    fsmeta: FsMeta = FsMeta()
    mbaddr: str = ""


class FsIds(pydantic.BaseModel):
    users: dict[str, int] | None = {}
    groups: dict[str, int] | None = {}


class FsSpec(pydantic.BaseModel):
    fsmeta: FsMeta = FsMeta()
    fsref: FsRef = FsRef()
    fsids: FsIds = FsIds()


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


def _verify_fsmeta(fsmeta: FsMeta) -> None:
    if not fsmeta.version:
        raise ConfException(f"non-valid meta version: {fsmeta}")
    if fsmeta.fmtvers != 1:
        raise ConfException(f"non-valid meta fmtvers: {fsmeta}")
    if not fsmeta.timestamp:
        raise ConfException(f"non-valid meta timestamp: {fsmeta}")


def _verify_fsref(fsref: FsRef) -> None:
    if len(fsref.mbaddr) != 64:
        raise ConfException(f"non-valid mbaddr: {fsref.mbaddr}")


def _verify_fsids(fsids: FsIds) -> None:
    if not fsids.users or not fsids.groups:
        raise ConfException("non-valid fsids mapping")


def _verify_spec(spec: FsSpec) -> None:
    _verify_fsmeta(spec.fsmeta)
    _verify_fsref(spec.fsref)
    _verify_fsids(spec.fsids)


def load_spec(path: Path) -> FsSpec:
    """Load and verify meta-ref json file into internal representation."""
    spec = FsSpec()
    with open(path, "rb") as f:
        try:
            jspec = json.load(f)
            spec = FsSpec(**jspec)
            _verify_spec(spec)
        except json.JSONDecodeError as jde:
            raise ConfException(f"bad spec file: {path}") from jde
        except pydantic.ValidationError as ve:
            raise ConfException(f"non-valid spec at: {path}") from ve
    return spec
