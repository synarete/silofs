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
#ifndef SILOFS_VBS_H_
#define SILOFS_VBS_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"

/* hash-map + LRU-queue of open blob-refs */
struct silofs_vbs_hq {
	struct silofs_listq      vbq_lru;
	struct silofs_list_head *vbq_htb;
	size_t                   vbq_htb_nelems;
};

/* virtual blob-storage using regular-files */
struct silofs_vbs {
	struct silofs_vbs_hq  vbs_hq;
	struct silofs_mdigest vbs_md;
	struct silofs_alloc  *vbs_alloc;
	int                   vbs_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_vbs_init(struct silofs_vbs *vbs, struct silofs_alloc *alloc);

void silofs_vbs_fini(struct silofs_vbs *vbs);

int silofs_vbs_open(struct silofs_vbs           *vbs,
                    const struct silofs_strview *repodir);

void silofs_vbs_close(struct silofs_vbs *vbs);

void silofs_vbs_relax(struct silofs_vbs *vbs);

void silofs_vbs_drop(struct silofs_vbs *vbs);

int silofs_vbs_sync(const struct silofs_vbs *vbs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_vbs_spawn_blob(struct silofs_vbs          *vbs,
                          const struct silofs_blobid *blobid);

int silofs_vbs_stage_blob(struct silofs_vbs          *vbs,
                          const struct silofs_blobid *blobid);

int silofs_vbs_stat_blob(struct silofs_vbs          *vbs,
                         const struct silofs_blobid *blobid,
                         struct stat                *out_st);

int silofs_vbs_require_blob(struct silofs_vbs          *vbs,
                            const struct silofs_blobid *blobid);

int silofs_vbs_require_bpos(struct silofs_vbs          *vbs,
                            const struct silofs_blobid *blobid, off_t pos);

int silofs_vbs_access_bpos(struct silofs_vbs          *vbs,
                           const struct silofs_blobid *blobid, off_t pos);

int silofs_vbs_remove_blob(struct silofs_vbs          *vbs,
                           const struct silofs_blobid *blobid);

int silofs_vbs_flush_blob(struct silofs_vbs          *vbs,
                          const struct silofs_blobid *blobid);

int silofs_vbs_punch_blob(struct silofs_vbs          *vbs,
                          const struct silofs_blobid *blobid);

int silofs_vbs_write_blob(struct silofs_vbs         *vbs,
                          const struct silofs_paddr *paddr,
                          const struct silofs_rovec *rovec);

int silofs_vbs_writev_blob(struct silofs_vbs         *vbs,
                           const struct silofs_paddr *paddr,
                           const struct iovec *iov, size_t cnt);

int silofs_vbs_read_blob(struct silofs_vbs         *vbs,
                         const struct silofs_paddr *paddr, void *buf,
                         size_t len);

#endif /* SILOFS_VBS_H_ */
