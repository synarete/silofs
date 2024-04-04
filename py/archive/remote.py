# SPDX-License-Identifier: GPL-3.0
import json
from pathlib import Path

from .blobs import BlobInfo
from .model import Catalog
from .utils import ArchiveException


class RemoteCtx:
    def __init__(self, archive_dir: Path) -> None:
        self.archive_dir = archive_dir.absolute()
        self.json_seps = (",", ": ")

    def check_args(self) -> None:
        if not self.archive_dir.exists():
            raise ArchiveException(f"not-exists: {self.archive_dir}")
        if not self.archive_dir.is_dir():
            raise ArchiveException(f"not a directory: {self.archive_dir}")

    def store_catalog(self, catalog: Catalog) -> None:
        path = self._path_of_meta(catalog.name)
        data = catalog.json()
        self._store_meta(path, data)

    def store_blob(self, blob_info: BlobInfo) -> None:
        self._store_blob_data(blob_info)
        self._store_blob_desc(blob_info)

    def _store_blob_data(self, blob_info: BlobInfo) -> None:
        path = self._path_of_blob(blob_info)
        data = blob_info.data.dat
        with open(path, "wb+") as fp:
            cnt = 0
            while cnt < len(data):
                nwr = fp.write(data[cnt:])
                cnt += nwr

    def _store_blob_desc(self, blob_info: BlobInfo) -> None:
        path = self._path_of_blob_desc(blob_info)
        data = blob_info.meta.json()
        self._store_meta(path, data)

    def _store_meta(self, path: Path, data: str) -> None:
        json_repr = json.loads(data)
        with open(path, "w+", encoding="utf-8") as fp:
            json.dump(json_repr, fp, indent=4, separators=self.json_seps)

    def _path_of_blob(self, blob_info: BlobInfo) -> Path:
        blob_meta = blob_info.meta
        return self._path_of(blob_meta.blobid.bid)

    def _path_of_blob_desc(self, blob_info: BlobInfo) -> Path:
        blob_meta = blob_info.meta
        return self._path_of_meta(blob_meta.blobid.bid)

    def _path_of_meta(self, name: str) -> Path:
        return self._path_of(name + ".json")

    def _path_of(self, name: str) -> Path:
        return self.archive_dir / name
