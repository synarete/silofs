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
#ifndef SILOFS_EXEC_H_
#define SILOFS_EXEC_H_

#include "infra.h"
#include "addr.h"
#include "flags.h"

#define SILOFS_SQENT_NREFS_MAX (32)

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
} silofs_attr_aligned64;

/* execution-context authentication */
struct silofs_task_auth {
	struct silofs_creds creds;
	struct timespec     ts;
	uint64_t            unique;
	uint32_t            opcode;
	pid_t               pid;
};

/* execution-context */
struct silofs_task_ctx {
	struct silofs_task_auth     t_auth;
	struct silofs_env          *t_env;
	const struct silofs_idsmap *t_idsm;
	const struct silofs_creds  *t_creds;
	struct silofs_repo         *t_repo;
	struct silofs_lcache       *t_lcache;
	struct silofs_submitq      *t_submitq;
	struct silofs_inode_info   *t_looseq;
	uint64_t                    t_upper_id;
	volatile int8_t             t_interrupt;
	volatile bool               t_fs_locked;
	bool                        t_ex_locked;
	bool                        t_exclusive;
	bool                        t_mrec_op;
	bool                        t_kwrite;
	bool                        t_runnable;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_flusher_init(struct silofs_flusher *flusher,
                        struct silofs_submitq *submitq);

void silofs_flusher_fini(struct silofs_flusher *flusher);

int silofs_flush_dirty(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *ii, int flags);

int silofs_flush_dirty_now(struct silofs_task_ctx *task);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_init(struct silofs_task_ctx *task, struct silofs_env *env);

void silofs_task_fini(struct silofs_task_ctx *task);

void silofs_task_set_creds(struct silofs_task_ctx *task, uid_t uid, gid_t gid,
                           mode_t umsk);

void silofs_task_update_umask(struct silofs_task_ctx *task, mode_t umask);

void silofs_task_set_ts(struct silofs_task_ctx *task, bool rt);

void silofs_task_update_by(struct silofs_task_ctx    *task,
                           struct silofs_submitq_ent *sqe);

int silofs_task_submit(struct silofs_task_ctx *task, bool all);

void silofs_task_enq_loose(struct silofs_task_ctx   *task,
                           struct silofs_inode_info *ii);

void silofs_lock_fs_by(struct silofs_task_ctx *task);

void silofs_unlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task);

struct silofs_sb_info *silofs_get_sbi(const struct silofs_task_ctx *task);

#endif /* SILOFS_EXEC_H_ */
