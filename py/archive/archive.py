# SPDX-License-Identifier: GPL-3.0
import typing
from pathlib import Path

from .blobs import BlobInfo
from .local import LocalCtx
from .model import ArchiveIndex, BlobMeta
from .remote import RemoteCtx


# pylint: disable=R0903
class ArchiveCtx:
    def __init__(
        self, repodir_name: Path, archive_dir: Path, passwd: str = ""
    ) -> None:
        self.local = LocalCtx(repodir_name, passwd)
        self.remote = RemoteCtx(archive_dir)

    def execute_archive(self) -> ArchiveIndex:
        self._pre_archive()
        blobs_meta = self._store_blobs()
        ar_index = self._make_index(blobs_meta)
        return ar_index

    def _make_index(self, blobs_meta: typing.List[BlobMeta]) -> ArchiveIndex:
        ar_index = ArchiveIndex()
        ar_index.name = self.local.meta.name
        ar_index.conf = self.local.meta.conf
        ar_index.blobs_meta = blobs_meta
        return ar_index

    def _store_blobs(self) -> typing.List[BlobMeta]:
        blobs_meta = []
        view = self.local.fetch_view()
        for ref_id in view.view:
            blob_data = self.local.fetch_ref(ref_id)
            blob_info = BlobInfo.create_by(ref_id, blob_data)
            self.remote.store_blob(blob_info)
            blobs_meta.append(blob_info.meta)
        return blobs_meta

    def _pre_archive(self) -> None:
        self.local.check_args()
        self.remote.check_args()
        self.local.check_cmd()
        self.local.load_meta()
        self.local.require_passwd()
