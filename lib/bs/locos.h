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
#ifndef SILOFS_LOCOS_H_
#define SILOFS_LOCOS_H_

#include "infra.h"
#include "str.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_locos_hq {
	struct silofs_listq      lhq_lru;
	struct silofs_list_head *lhq_htb;
	size_t                   lhq_htb_nelems;
};

/* local object-store */
struct silofs_locos {
	struct silofs_locos_hq los_hq;
	struct silofs_alloc   *los_alloc;
	int                    los_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_locos_init(struct silofs_locos *locos, struct silofs_alloc *alloc);

void silofs_locos_fini(struct silofs_locos *locos);

int silofs_locos_open(struct silofs_locos         *locos,
                      const struct silofs_strview *repodir);

void silofs_locos_close(struct silofs_locos *locos);

void silofs_locos_relax_cache(struct silofs_locos *locos);

void silofs_locos_drop_cache(struct silofs_locos *locos);

int silofs_locos_create_blob(struct silofs_locos        *locos,
                             const struct silofs_blobid *blobid);

int silofs_locos_stat_blob(struct silofs_locos        *locos,
                           const struct silofs_blobid *blobid,
                           struct stat                *out_st);

int silofs_locos_require_blob(struct silofs_locos        *locos,
                              const struct silofs_blobid *blobid);

int silofs_locos_remove_blob(struct silofs_locos        *locos,
                             const struct silofs_blobid *blobid);

int silofs_locos_flush_blob(struct silofs_locos        *locos,
                            const struct silofs_blobid *blobid);

int silofs_locos_write_blob(struct silofs_locos       *locos,
                            const struct silofs_baddr *baddr,
                            const struct silofs_rovec *rovec);

int silofs_locos_read_blob(struct silofs_locos       *locos,
                           const struct silofs_baddr *baddr,
                           const struct silofs_rwvec *rwvec);

#endif /* SILOFS_LOCOS_H_ */
