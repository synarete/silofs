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
#ifndef SILOFS_REGBS_H_
#define SILOFS_REGBS_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_regbs_hq {
	struct silofs_listq      rgq_lru;
	struct silofs_list_head *rgq_htb;
	size_t                   rgq_htb_nelems;
};

/* regular-files as blob-storage */
struct silofs_regbs {
	struct silofs_regbs_hq rg_hq;
	struct silofs_mdigest  rg_md;
	struct silofs_alloc   *rg_alloc;
	int                    rg_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_regbs_init(struct silofs_regbs *regbs, struct silofs_alloc *alloc);

void silofs_regbs_fini(struct silofs_regbs *regbs);

int silofs_regbs_open(struct silofs_regbs         *regbs,
                      const struct silofs_strview *repodir);

void silofs_regbs_close(struct silofs_regbs *regbs);

void silofs_regbs_relax(struct silofs_regbs *regbs);

void silofs_regbs_drop(struct silofs_regbs *regbs);

int silofs_regbs_sync(const struct silofs_regbs *regbs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_regbs_spawn_blob(struct silofs_regbs        *regbs,
                            const struct silofs_blobid *blobid);

int silofs_regbs_stage_blob(struct silofs_regbs        *regbs,
                            const struct silofs_blobid *blobid);

int silofs_regbs_stat_blob(struct silofs_regbs        *regbs,
                           const struct silofs_blobid *blobid,
                           struct stat                *out_st);

int silofs_regbs_require_blob(struct silofs_regbs        *regbs,
                              const struct silofs_blobid *blobid);

int silofs_regbs_require_bpos(struct silofs_regbs        *regbs,
                              const struct silofs_blobid *blobid, off_t pos);

int silofs_regbs_access_bpos(struct silofs_regbs        *regbs,
                             const struct silofs_blobid *blobid, off_t pos);

int silofs_regbs_remove_blob(struct silofs_regbs        *regbs,
                             const struct silofs_blobid *blobid);

int silofs_regbs_flush_blob(struct silofs_regbs        *regbs,
                            const struct silofs_blobid *blobid);

int silofs_regbs_punch_blob(struct silofs_regbs        *regbs,
                            const struct silofs_blobid *blobid);

int silofs_regbs_write_blob(struct silofs_regbs       *regbs,
                            const struct silofs_paddr *paddr,
                            const struct silofs_rovec *rovec);

int silofs_regbs_writev_blob(struct silofs_regbs       *regbs,
                             const struct silofs_paddr *paddr,
                             const struct iovec *iov, size_t cnt);

int silofs_regbs_read_blob(struct silofs_regbs       *regbs,
                           const struct silofs_paddr *paddr,
                           const struct silofs_rwvec *rwvec);

#endif /* SILOFS_REGBS_H_ */
