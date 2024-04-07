# SPDX-License-Identifier: GPL-3.0
import json
import typing
from pathlib import Path
from uuid import UUID, uuid4

import pydantic

import toml

from .expect import ExpectException


class FsId(pydantic.BaseModel):
    uuid: UUID = uuid4()


class BConf(pydantic.BaseModel):
    fsid: FsId = FsId()
    users: typing.Optional[typing.Dict[str, int]] = {}
    groups: typing.Optional[typing.Dict[str, int]] = {}


def load_bconf(path: Path) -> BConf:
    try:
        toml_data = toml.load(path)
        json_data = json.dumps(toml_data)
        json_conf = json.loads(json_data)
        return BConf(**json_conf)
    except toml.TomlDecodeError as tde:
        raise ExpectException(f"bad fs boot-conf toml: {path}") from tde
    except pydantic.ValidationError as ve:
        raise ExpectException(f"non-valid fs boot-conf: {path}") from ve
