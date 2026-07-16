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

#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>

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

int silofs_dstor_spawn_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_stage_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_stat_blob(struct silofs_dstor        *dstor,
                           const struct silofs_blobid *blobid,
                           struct stat                *out_st);

int silofs_dstor_require_blob(struct silofs_dstor        *dstor,
                              const struct silofs_blobid *blobid);

int silofs_dstor_require_blob_at(struct silofs_dstor        *dstor,
                                 const struct silofs_blobid *blobid,
                                 off_t                       pos);

int silofs_dstor_access_blob_at(struct silofs_dstor        *dstor,
                                const struct silofs_blobid *blobid, off_t pos);

int silofs_dstor_remove_blob(struct silofs_dstor        *dstor,
                             const struct silofs_blobid *blobid);

int silofs_dstor_flush_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_punch_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_read_blob_at(struct silofs_dstor        *dstor,
                              const struct silofs_blobid *blobid, off_t pos,
                              void *buf, size_t len);

int silofs_dstor_write_blob_at(struct silofs_dstor        *dstor,
                               const struct silofs_blobid *blobid, off_t pos,
                               const void *buf, size_t len);

int silofs_dstor_writev_blob_at(struct silofs_dstor        *dstor,
                                const struct silofs_blobid *blobid, off_t pos,
                                const struct iovec *iov, size_t n);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_stat_blob_by(struct silofs_dstor         *dstor,
                              const struct silofs_blobidx *blobidx,
                              struct stat                 *out_st);

int silofs_dstor_save_blob_by(struct silofs_dstor         *dstor,
                              const struct silofs_blobidx *blobidx,
                              const void *buf, size_t len);

int silofs_dstor_load_blob_by(struct silofs_dstor         *dstor,
                              const struct silofs_blobidx *blobidx, void *buf,
                              size_t len);

int silofs_dstor_unref_blob_by(struct silofs_dstor         *dstor,
                               const struct silofs_blobidx *blobidx);

#endif /* SILOFS_DSTOR_H_ */
