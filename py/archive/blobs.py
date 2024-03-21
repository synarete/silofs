# SPDX-License-Identifier: GPL-3.0
import base64
import hashlib
import typing

from . import model


class BlobData:
    def __init__(self, dat: bytes) -> None:
        self.dat = dat

    def size(self) -> int:
        return len(self.dat)

    def calc_id(self) -> typing.Tuple[model.BlobID, model.HashFn]:
        digest = hashlib.sha256(self.dat).hexdigest()
        hashfn = model.HashFn.SHA256
        return (model.BlobID(bid=digest), hashfn)

    @staticmethod
    def from_base64(ascii_dat: str):
        dat = base64.b64decode(ascii_dat.strip())
        return BlobData(dat)


# pylint: disable=R0903
class BlobInfo:
    def __init__(self, meta: model.BlobMeta, data: BlobData) -> None:
        self.meta = meta
        self.data = data

    @staticmethod
    def create_by(refid: model.FsRefID, blob_data: BlobData):
        (bid, hfn) = blob_data.calc_id()
        bsz = blob_data.size()
        meta = model.BlobMeta(refid=refid, blobid=bid, hashfn=hfn, size=bsz)
        return BlobInfo(meta, blob_data)
