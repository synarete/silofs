# SPDX-License-Identifier: GPL-3.0
import datetime
import enum
import typing
from uuid import UUID, uuid4

import pydantic


class Version(str, enum.Enum):
    V1 = "1"


class HashFn(str, enum.Enum):
    SHA256 = "sha256"


class FsId(pydantic.BaseModel):
    uuid: UUID = uuid4()


class FsConf(pydantic.BaseModel):
    fsid: FsId = FsId()
    users: typing.Optional[typing.Dict[str, int]] = {}
    groups: typing.Optional[typing.Dict[str, int]] = {}


class FsRefID(pydantic.BaseModel):
    version: Version = Version.V1
    rid: str


class BlobID(pydantic.BaseModel):
    version: Version = Version.V1
    bid: str


class BlobMeta(pydantic.BaseModel):
    version: Version = Version.V1
    refid: FsRefID
    blobid: BlobID
    hashfn: HashFn
    size: int
    btime: datetime.datetime = datetime.datetime.now()


class Catalog(pydantic.BaseModel):
    version: Version = Version.V1
    name: str = ""
    conf: FsConf = FsConf()
    btime: datetime.datetime = datetime.datetime.now()
    blobids: typing.Optional[typing.List[BlobID]] = []
