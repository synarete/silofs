# SPDX-License-Identifier: GPL-3.0
import json
import typing
from pathlib import Path
from uuid import UUID, uuid4

import pydantic

import toml

from .expect import ExpectException


class TestRemotesConfig(pydantic.BaseModel):
    postgresql_repo_url: str = "https://git.postgresql.org/git/postgresql.git"
    rsync_repo_url: str = "git://git.samba.org/rsync.git"
    git_repo_url: str = "https://github.com/git/git.git"
    silofs_repo_url: str = "https://github.com/synarete/silofs"


class TestConfig(pydantic.BaseModel):
    basedir: Path = Path(".").resolve(strict=True)
    mntdir: Path = Path(".").resolve(strict=True)
    password: str = "123456"
    use_stdalloc: bool = False
    allow_coredump: bool = False
    remotes: TestRemotesConfig = TestRemotesConfig()


class FsId(pydantic.BaseModel):
    uuid: UUID = uuid4()


class FsBootConf(pydantic.BaseModel):
    fsid: FsId = FsId()
    users: typing.Optional[typing.Dict[str, int]] = {}
    groups: typing.Optional[typing.Dict[str, int]] = {}


def _load_toml_as_json(path: Path) -> str:
    toml_data = toml.load(path)
    return json.dumps(toml_data)


def load_config(path: Path) -> TestConfig:
    try:
        json_conf = json.loads(_load_toml_as_json(path))
        return TestConfig(**json_conf)
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
