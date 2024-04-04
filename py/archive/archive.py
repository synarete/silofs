# SPDX-License-Identifier: GPL-3.0
import typing
from pathlib import Path

from .blobs import BlobInfo
from .local import LocalCtx
from .model import BlobMeta, Catalog
from .remote import RemoteCtx


class ArchiveCtx:
    def __init__(
        self,
        repodir_name: Path,
        archive_dir: Path,
        passwd: str = "",
        restore_mode: bool = False,
    ) -> None:
        self.local = LocalCtx(repodir_name, passwd)
        self.remote = RemoteCtx(archive_dir)
        self.restore_mode = restore_mode

    def execute_archive(self) -> None:
        self._pre_archive()
        blobs_meta = self._store_blobs()
        catalog = self._make_catalog(blobs_meta)
        self._store_catalog(catalog)

    def execute_restore(self) -> None:
        pass

    def _store_catalog(self, catalog: Catalog) -> None:
        self.remote.store_catalog(catalog)

    def _make_catalog(self, blobs_meta: typing.List[BlobMeta]) -> Catalog:
        catalog = Catalog()
        catalog.name = self.local.meta.name
        catalog.conf = self.local.meta.conf
        catalog.blobids = [meta.blobid for meta in blobs_meta]
        return catalog

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
        self.local.check_cmd()
        self.local.check_args(self.restore_mode)
        self.remote.check_args()
        self.local.load_meta()
        self.local.require_passwd()
