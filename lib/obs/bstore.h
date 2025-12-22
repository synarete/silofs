/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef SILOFS_BSTORE_H_
#define SILOFS_BSTORE_H_

#include "infra.h"
#include "crypto.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_bstore_hq {
	struct silofs_listq      bsq_lru;
	struct silofs_list_head *bsq_htb;
	size_t                   bsq_htb_nelems;
};

/* virtual blob-storage using regular-files */
struct silofs_bstore {
	struct silofs_bstore_hq bs_hq;
	struct silofs_mdigest   bs_md;
	struct silofs_alloc    *bs_alloc;
	int                     bs_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_alloc  *alloc);

void silofs_bstore_fini(struct silofs_bstore *bstore);

int silofs_bstore_open(struct silofs_bstore        *bstore,
                       const struct silofs_strview *repodir);

void silofs_bstore_close(struct silofs_bstore *bstore);

void silofs_bstore_relax(struct silofs_bstore *bstore);

void silofs_bstore_drop(struct silofs_bstore *bstore);

int silofs_bstore_sync(const struct silofs_bstore *bstore);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_spawn_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid);

int silofs_bstore_stage_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid);

int silofs_bstore_stat_blob(struct silofs_bstore       *bstore,
                            const struct silofs_blobid *blobid,
                            struct stat                *out_st);

int silofs_bstore_require_blob(struct silofs_bstore       *bstore,
                               const struct silofs_blobid *blobid);

int silofs_bstore_require_blob_at(struct silofs_bstore       *bstore,
                                  const struct silofs_blobid *blobid,
                                  off_t                       pos);

int silofs_bstore_access_blob_at(struct silofs_bstore       *bstore,
                                 const struct silofs_blobid *blobid,
                                 off_t                       pos);

int silofs_bstore_remove_blob(struct silofs_bstore       *bstore,
                              const struct silofs_blobid *blobid);

int silofs_bstore_flush_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid);

int silofs_bstore_punch_blob(struct silofs_bstore       *bstore,
                             const struct silofs_blobid *blobid);

int silofs_bstore_read_blob_at(struct silofs_bstore       *bstore,
                               const struct silofs_blobid *blobid, off_t pos,
                               void *buf, size_t len);

int silofs_bstore_write_blob_at(struct silofs_bstore       *bstore,
                                const struct silofs_blobid *blobid, off_t pos,
                                const void *buf, size_t len);

int silofs_bstore_writev_blob_at(struct silofs_bstore       *bstore,
                                 const struct silofs_blobid *blobid, off_t pos,
                                 const struct iovec *iov, size_t cnt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_stat_mbr(struct silofs_bstore      *bstore,
                           const struct silofs_mbref *mbref,
                           struct stat               *out_st);

int silofs_bstore_save_mbr(struct silofs_bstore      *bstore,
                           const struct silofs_mbref *mbref, const void *buf,
                           size_t len);

int silofs_bstore_load_mbr(struct silofs_bstore      *bstore,
                           const struct silofs_mbref *mbref, void *buf,
                           size_t len);

int silofs_bstore_unref_mbr(struct silofs_bstore      *bstore,
                            const struct silofs_mbref *mbref);

#endif /* SILOFS_BSTORE_H_ */
