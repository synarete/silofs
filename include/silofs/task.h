/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

/* execution-context task per file-system operation */
struct silofs_task {
	struct silofs_uber     *t_uber;
	struct silofs_submitq  *t_submitq;
	struct silofs_listq     t_pendq;
	struct silofs_oper      t_oper;
	uint64_t                t_apex_id;
	volatile int            t_interrupt;
	int                     t_may_flush;
};

/* submit reference into view within underlying block */
struct silofs_submit_ref {
	struct silofs_bk_info      *bki;
	const union silofs_view    *view;
	size_t                      len;
};

/* submission queue entry */
struct silofs_submitq_entry {
	struct silofs_mutex         mu;
	struct silofs_list_head     qlh;
	struct silofs_list_head     tlh;
	struct silofs_alloc        *alloc;
	struct silofs_task         *task;
	struct silofs_blobf        *blobf;
	struct silofs_submit_ref    ref[32];
	struct silofs_blobid        blobid;
	uint64_t        uniq_id;
	void           *buf;
	loff_t          off;
	size_t          len;
	size_t          cnt;
	int             hold_refs;
	volatile int    status;
};

/* submission flush queue */
struct silofs_submitq {
	struct silofs_listq     smq_listq;
	struct silofs_mutex     smq_mutex;
	uint64_t                smq_apex_id;
};

/* commit-queues flush set */
struct silofs_commitqs {
	struct silofs_rwlock    cqs_rwlock;
	struct silofs_submitq   cqs_set[4];
	struct silofs_alloc    *cqs_alloc;
	uint64_t                cqs_apex_cid;
	volatile int            cqs_active;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_sqe_append_ref(struct silofs_submitq_entry *sqe,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_snode_info *si);

int silofs_sqe_assign_buf(struct silofs_submitq_entry *sqe);

void silofs_sqe_bind_blobf(struct silofs_submitq_entry *sqe,
                           struct silofs_blobf *blobf);

void silofs_sqe_increfs(struct silofs_submitq_entry *sqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber);

void silofs_task_fini(struct silofs_task *task);

void silofs_task_set_creds(struct silofs_task *task,
                           uid_t uid, gid_t gid, pid_t pid);

void silofs_task_set_umask(struct silofs_task *task, mode_t umask);

void silofs_task_set_ts(struct silofs_task *task, bool rt);

int silofs_task_mk_sqe(struct silofs_task *task,
                       struct silofs_submitq_entry **out_sqe);

void silofs_task_rm_sqe(struct silofs_task *task,
                        struct silofs_submitq_entry *sqe);

void silofs_task_enq_sqe(struct silofs_task *task,
                         struct silofs_submitq_entry *sqe);

int silofs_task_submit(struct silofs_task *task, bool all);

int silofs_task_complete(struct silofs_task *task);

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task);

bool silofs_task_has_kcopy(const struct silofs_task *task);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_submitq_init(struct silofs_submitq *smq);

void silofs_submitq_fini(struct silofs_submitq *smq);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_num_worker_threads(void);

#endif /* SILOFS_TASK_H_ */
