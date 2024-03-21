# SPDX-License-Identifier: GPL-3.0
import json
from pathlib import Path

from .blobs import BlobInfo
from .utils import ArchiveException


class RemoteCtx:
    def __init__(self, archive_dir: Path) -> None:
        self.archive_dir = archive_dir.absolute()

    def check_args(self) -> None:
        if not self.archive_dir.exists():
            raise ArchiveException(f"not-exists: {self.archive_dir}")
        if not self.archive_dir.is_dir():
            raise ArchiveException(f"not a directory: {self.archive_dir}")

    def store_blob(self, blob_info: BlobInfo) -> None:
        self._store_blob_data(blob_info)
        self._store_blob_meta(blob_info)

    def _store_blob_data(self, blob_info: BlobInfo) -> None:
        path = self._data_path_of(blob_info)
        data = blob_info.data.dat
        with open(path, "wb+") as fp:
            cnt = 0
            while cnt < len(data):
                nwr = fp.write(data[cnt:])
                cnt += nwr

    def _store_blob_meta(self, blob_info: BlobInfo) -> None:
        path = self._meta_path_of(blob_info)
        data = json.loads(blob_info.meta.json())
        with open(path, "w+", encoding="utf-8") as fp:
            json.dump(data, fp, indent=4, separators=(",", ": "))

    def _data_path_of(self, blob_info: BlobInfo) -> Path:
        blob_meta = blob_info.meta
        return self.archive_dir / blob_meta.blobid.bid

    def _meta_path_of(self, blob_info: BlobInfo) -> Path:
        data_path = self._data_path_of(blob_info)
        return Path(str(data_path) + ".json")
