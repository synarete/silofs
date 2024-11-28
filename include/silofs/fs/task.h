/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_TASK_H_
#define SILOFS_TASK_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/fs/types.h>

#define SILOFS_SQENT_NREFS_MAX (32)

/* current file-system operation */
struct silofs_oper {
	struct silofs_creds op_creds;
	pid_t               op_pid;
	uint64_t            op_unique;
	uint32_t            op_code;
};

/* execution-context task per file-system operation */
struct silofs_task {
	struct silofs_fsenv      *t_fsenv;
	struct silofs_submitq    *t_submitq;
	struct silofs_inode_info *t_looseq;
	struct silofs_oper        t_oper;
	uint64_t                  t_apex_id;
	volatile int8_t           t_interrupt;
	volatile bool             t_fs_locked;
	bool                      t_ex_locked;
	bool                      t_exclusive;
	bool                      t_uber_op;
	bool                      t_kwrite;
};

/* submit reference into view within underlying block */
struct silofs_submit_ref {
	struct silofs_llink       llink;
	const struct silofs_view *view;
	enum silofs_ltype         ltype;
};

/* submission queue entry */
struct silofs_submitq_ent {
	struct iovec              iov[SILOFS_SQENT_NREFS_MAX];
	struct silofs_lnode_info *lni[SILOFS_SQENT_NREFS_MAX];
	struct silofs_list_head   qlh;
	struct silofs_fsenv      *fsenv;
	struct silofs_alloc      *alloc;
	struct silofs_laddr       laddr;
	uint64_t                  uniq_id;
	uint32_t                  cnt;
	uint32_t                  tx_count;
	uint32_t                  tx_index;
	int                       hold_refs;
	volatile int              status;
	enum silofs_ltype         ltype;
};

/* submission flush queue */
struct silofs_submitq {
	struct silofs_listq  smq_listq;
	struct silofs_mutex  smq_mutex;
	struct silofs_alloc *smq_alloc;
	uint64_t             smq_apex_id;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_submitq_ent *silofs_sqe_from_qlh(struct silofs_list_head *qlh);

bool silofs_sqe_append_ref(struct silofs_submitq_ent *sqe,
			   const struct silofs_laddr *laddr,
			   struct silofs_lnode_info  *lni);

int silofs_sqe_assign_iovs(struct silofs_submitq_ent      *sqe,
			   const struct silofs_submit_ref *refs_arr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_init(struct silofs_task *task, struct silofs_fsenv *fsenv);

void silofs_task_fini(struct silofs_task *task);

void silofs_task_set_creds(struct silofs_task *task, uid_t uid, gid_t gid,
			   mode_t umsk);

void silofs_task_update_umask(struct silofs_task *task, mode_t umask);

void silofs_task_set_ts(struct silofs_task *task, bool rt);

void silofs_task_update_by(struct silofs_task        *task,
			   struct silofs_submitq_ent *sqe);

int silofs_task_submit(struct silofs_task *task, bool all);

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task);

struct silofs_lcache *silofs_task_lcache(const struct silofs_task *task);

struct silofs_repo *silofs_task_repo(const struct silofs_task *task);

const struct silofs_idsmap *silofs_task_idsmap(const struct silofs_task *task);

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task);

void silofs_task_enq_loose(struct silofs_task       *task,
			   struct silofs_inode_info *ii);

void silofs_task_lock_fs(struct silofs_task *task);

void silofs_task_unlock_fs(struct silofs_task *task);

void silofs_task_rwlock_fs(struct silofs_task *task);

void silofs_task_rwunlock_fs(struct silofs_task *task);

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

#endif /* SILOFS_TASK_H_ */
