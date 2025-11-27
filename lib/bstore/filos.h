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
#ifndef SILOFS_FILOS_H_
#define SILOFS_FILOS_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_filos_hq {
	struct silofs_listq      lhq_lru;
	struct silofs_list_head *lhq_htb;
	size_t                   lhq_htb_nelems;
};

/* local object-store */
struct silofs_filos {
	struct silofs_filos_hq los_hq;
	struct silofs_mdigest  los_md;
	struct silofs_alloc   *los_alloc;
	int                    los_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_filos_init(struct silofs_filos *filos, struct silofs_alloc *alloc);

void silofs_filos_fini(struct silofs_filos *filos);

int silofs_filos_open(struct silofs_filos         *filos,
                      const struct silofs_strview *repodir);

void silofs_filos_close(struct silofs_filos *filos);

void silofs_filos_relax(struct silofs_filos *filos);

void silofs_filos_drop(struct silofs_filos *filos);

int silofs_filos_sync(const struct silofs_filos *filos);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_filos_spawn_blob(struct silofs_filos        *filos,
                            const struct silofs_blobid *blobid);

int silofs_filos_stage_blob(struct silofs_filos        *filos,
                            const struct silofs_blobid *blobid);

int silofs_filos_stat_blob(struct silofs_filos        *filos,
                           const struct silofs_blobid *blobid,
                           struct stat                *out_st);

int silofs_filos_require_blob(struct silofs_filos        *filos,
                              const struct silofs_blobid *blobid);

int silofs_filos_require_bpos(struct silofs_filos        *filos,
                              const struct silofs_blobid *blobid, off_t pos);

int silofs_filos_access_bpos(struct silofs_filos        *filos,
                             const struct silofs_blobid *blobid, off_t pos);

int silofs_filos_remove_blob(struct silofs_filos        *filos,
                             const struct silofs_blobid *blobid);

int silofs_filos_flush_blob(struct silofs_filos        *filos,
                            const struct silofs_blobid *blobid);

int silofs_filos_punch_blob(struct silofs_filos        *filos,
                            const struct silofs_blobid *blobid);

int silofs_filos_write_blob(struct silofs_filos       *filos,
                            const struct silofs_paddr *paddr,
                            const struct silofs_rovec *rovec);

int silofs_filos_writev_blob(struct silofs_filos       *filos,
                             const struct silofs_paddr *paddr,
                             const struct iovec *iov, size_t cnt);

int silofs_filos_read_blob(struct silofs_filos       *filos,
                           const struct silofs_paddr *paddr,
                           const struct silofs_rwvec *rwvec);

#endif /* SILOFS_FILOS_H_ */
