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
#ifndef SILOFS_FLUSH_H_
#define SILOFS_FLUSH_H_

#include "infra.h"
#include "addr.h"

#define SILOFS_SQENT_NREFS_MAX (32)
#define SILOFS_COMMIT_LEN_MAX SILOFS_MEGA
#define SILOFS_CID_ALL        UINT64_MAX

/* submit reference into view within underlying block */
struct silofs_submit_ref {
	struct silofs_llink       llink;
	const struct silofs_view *view;
	enum silofs_mtype         mtype;
};

/* submission queue entry */
struct silofs_submitq_ent {
	struct iovec              iov[SILOFS_SQENT_NREFS_MAX];
	struct silofs_lnode_info *lni[SILOFS_SQENT_NREFS_MAX];
	struct silofs_list_head   qlh;
	struct silofs_env        *env;
	struct silofs_alloc      *alloc;
	struct silofs_laddr       laddr_base;
	size_t                    len;
	uint64_t                  uniq_id;
	uint32_t                  cnt;
	uint32_t                  tx_count;
	uint32_t                  tx_index;
	int                       hold_refs;
	volatile int              status;
	enum silofs_mtype         mtype;
};

/* submission flush queue */
struct silofs_submitq {
	struct silofs_listq  smq_listq;
	struct silofs_mutex  smq_mutex;
	struct silofs_alloc *smq_alloc;
	uint64_t             smq_upper_id;
};

/* dirty-elements as ordered set */
struct silofs_dset {
	struct silofs_lnode_info *ds_preq;
	struct silofs_lnode_info *ds_postq;
	struct silofs_avl         ds_avl;
};

/* flush-to-stable controller */
struct silofs_flusher {
	struct silofs_submit_ref  sref[SILOFS_SQENT_NREFS_MAX];
	struct silofs_dset        dset[3];
	struct silofs_listq       txq;
	struct silofs_submitq    *submitq;
	struct silofs_task_ctx   *task;
	struct silofs_sb_info    *sbi;
	struct silofs_inode_info *ii;
	uint32_t                  tx_count;
	int                       flags;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_submitq_ent *silofs_sqe_from_qlh(struct silofs_list_head *qlh);

bool silofs_sqe_append_ref(struct silofs_submitq_ent *sqe,
                           const struct silofs_laddr *laddr,
                           struct silofs_lnode_info  *lni);

int silofs_sqe_assign_iovs(struct silofs_submitq_ent      *sqe,
                           const struct silofs_submit_ref *refs_arr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sqe_increfs(struct silofs_submitq_ent *sqe);

int silofs_submitq_init(struct silofs_submitq *smq,
                        struct silofs_alloc   *alloc);

void silofs_submitq_fini(struct silofs_submitq *smq);

void silofs_submitq_enqueue(struct silofs_submitq     *smq,
                            struct silofs_submitq_ent *sqe);

int silofs_submitq_new_sqe(struct silofs_submitq      *smq,
                           struct silofs_submitq_ent **out_sqe);

void silofs_submitq_del_sqe(struct silofs_submitq     *smq,
                            struct silofs_submitq_ent *sqe);

int silofs_submitq_apply(struct silofs_submitq *smq, uint64_t id);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_flusher_init(struct silofs_flusher *flusher,
                        struct silofs_submitq *submitq);

void silofs_flusher_fini(struct silofs_flusher *flusher);

int silofs_flush_dirty(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *ii, int flags);

int silofs_flush_dirty_now(struct silofs_task_ctx *task);

#endif /* SILOFS_FLUSH_H_ */
