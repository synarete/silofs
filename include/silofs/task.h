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
	struct silofs_lock      t_lock;
	struct silofs_uber     *t_uber;
	struct silofs_listq     t_pendq;
	struct silofs_oper      t_oper;
	volatile int            t_interrupt;
};

/* commit's reference within underlying block */
struct silofs_commit_ref {
	struct silofs_bk_info      *bki;
	const union silofs_view    *view;
	size_t                      len;
};

/* flush commit control object */
struct silofs_commit_info {
	struct silofs_list_head     tlh;
	struct silofs_task         *task;
	struct silofs_blobref_info *bri;
	struct silofs_commit_ref    ref[32];
	struct silofs_blobid        bid;
	void  *buf;
	loff_t off;
	size_t len;
	size_t cnt;
	int status;
	bool done;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_cmi_append_ref(struct silofs_commit_info *cmi,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_snode_info *si);

int silofs_cmi_assign_buf(struct silofs_commit_info *cmi);

void silofs_cmi_bind_bri(struct silofs_commit_info *cmi,
                         struct silofs_blobref_info *bri);

int silofs_cmi_write_buf(const struct silofs_commit_info *cmi);

void silofs_cmi_increfs(struct silofs_commit_info *cmi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber);

void silofs_task_fini(struct silofs_task *task);

void silofs_task_set_creds(struct silofs_task *task,
                           uid_t uid, gid_t gid, pid_t pid);

void silofs_task_set_umask(struct silofs_task *task, mode_t umask);

void silofs_task_set_ts(struct silofs_task *task, bool rt);

int silofs_task_make_commit(struct silofs_task *task,
                            struct silofs_commit_info **out_cmi);

int silofs_task_let_complete(struct silofs_task *task);

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task);

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task);

#endif /* SILOFS_TASK_H_ */
