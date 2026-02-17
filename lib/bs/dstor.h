/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#ifndef SILOFS_DSTOR_H_
#define SILOFS_DSTOR_H_

#include "infra.h"
#include "crypto.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_dstor_hq {
	struct silofs_listq      dsq_lru;
	struct silofs_list_head *dsq_htb;
	size_t                   dsq_htb_nelems;
};

/* blob-storage using regular files within flat directory */
struct silofs_dstor {
	struct silofs_dstor_hq   ds_hq;
	struct silofs_mdigest_hd ds_md;
	struct silofs_alloc     *ds_alloc;
	int                      ds_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_init(struct silofs_dstor *dstor, struct silofs_alloc *alloc);

void silofs_dstor_fini(struct silofs_dstor *dstor);

int silofs_dstor_open(struct silofs_dstor *dstor, int root_dfd);

void silofs_dstor_close(struct silofs_dstor *dstor);

void silofs_dstor_relax(struct silofs_dstor *dstor);

void silofs_dstor_drop(struct silofs_dstor *dstor);

int silofs_dstor_sync(const struct silofs_dstor *dstor);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_spawn_blob(struct silofs_dstor           *dstor,
                            const struct silofs_blobid56b *blobid56b);

int silofs_dstor_stage_blob(struct silofs_dstor           *dstor,
                            const struct silofs_blobid56b *blobid56b);

int silofs_dstor_stat_blob(struct silofs_dstor           *dstor,
                           const struct silofs_blobid56b *blobid56b,
                           struct stat                   *out_st);

int silofs_dstor_require_blob(struct silofs_dstor           *dstor,
                              const struct silofs_blobid56b *blobid56b);

int silofs_dstor_require_blob_at(struct silofs_dstor           *dstor,
                                 const struct silofs_blobid56b *blobid56b,
                                 off_t                          pos);

int silofs_dstor_access_blob_at(struct silofs_dstor           *dstor,
                                const struct silofs_blobid56b *blobid56b,
                                off_t                          pos);

int silofs_dstor_remove_blob(struct silofs_dstor           *dstor,
                             const struct silofs_blobid56b *blobid56b);

int silofs_dstor_flush_blob(struct silofs_dstor           *dstor,
                            const struct silofs_blobid56b *blobid56b);

int silofs_dstor_punch_blob(struct silofs_dstor           *dstor,
                            const struct silofs_blobid56b *blobid56b);

int silofs_dstor_read_blob_at(struct silofs_dstor           *dstor,
                              const struct silofs_blobid56b *blobid56b,
                              off_t pos, void *buf, size_t len);

int silofs_dstor_write_blob_at(struct silofs_dstor           *dstor,
                               const struct silofs_blobid56b *blobid56b,
                               off_t pos, const void *buf, size_t len);

int silofs_dstor_writev_blob_at(struct silofs_dstor           *dstor,
                                const struct silofs_blobid56b *blobid56b,
                                off_t pos, const struct iovec *iov,
                                size_t cnt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_stat_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref,
                          struct stat               *out_st);

int silofs_dstor_save_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref, const void *buf,
                          size_t len);

int silofs_dstor_load_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref, void *buf,
                          size_t len);

int silofs_dstor_unref_mbr(struct silofs_dstor       *dstor,
                           const struct silofs_mbref *mbref);

#endif /* SILOFS_DSTOR_H_ */
