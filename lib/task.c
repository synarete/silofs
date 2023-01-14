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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>


static struct silofs_alloc *cmi_alloc(const struct silofs_commit_info *cmi)
{
	return task_alloc(cmi->task);
}

static int cmi_setup_buf(struct silofs_commit_info *cmi)
{
	cmi->buf = silofs_allocate(cmi_alloc(cmi), cmi->len);
	return unlikely(cmi->buf == NULL) ? -ENOMEM : 0;
}

static void cmi_reset_buf(struct silofs_commit_info *cmi)
{
	if (likely(cmi->buf != NULL)) {
		silofs_deallocate(cmi_alloc(cmi), cmi->buf, cmi->len);
	}
	cmi->buf = NULL;
}

static bool cmi_isappendable(const struct silofs_commit_info *cmi,
                             const struct silofs_oaddr *oaddr)
{
	if (cmi->cnt == 0) {
		return true;
	}
	if (cmi->cnt == ARRAY_SIZE(cmi->si)) {
		return false;
	}
	if (oaddr->pos != off_end(cmi->off, cmi->len)) {
		return false;
	}
	if ((cmi->len + oaddr->len) > SILOFS_MEGA) {
		return false;
	}
	if (!blobid_isequal(&oaddr->bka.blobid, &cmi->bid)) {
		return false;
	}
	return true;
}

bool silofs_cmi_append_ref(struct silofs_commit_info *cmi,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_snode_info *si)
{
	if (!cmi_isappendable(cmi, oaddr)) {
		return false;
	}
	if (cmi->cnt == 0) {
		blobid_assign(&cmi->bid, &oaddr->bka.blobid);
		cmi->off = oaddr->pos;
	}
	cmi->si[cmi->cnt] = si;
	cmi->cnt += 1;
	cmi->len += si->s_view_len;
	return true;
}

int silofs_cmi_assign_buf(struct silofs_commit_info *cmi)
{
	const struct silofs_snode_info *si;
	uint8_t *dst = NULL;
	int err;

	err = cmi_setup_buf(cmi);
	if (err) {
		return err;
	}
	dst = cmi->buf;
	for (size_t i = 0; i < cmi->cnt; ++i) {
		si = cmi->si[i];
		memcpy(dst, si->s_view, si->s_view_len);
		dst += si->s_view_len;
	}
	return 0;
}

void silofs_cmi_bind_bri(struct silofs_commit_info *cmi,
                         struct silofs_blobref_info *bri)
{
	if (cmi->bri != NULL) {
		bri_decref(cmi->bri);
		cmi->bri = NULL;
	}
	if (bri != NULL) {
		cmi->bri = bri;
		bri_incref(cmi->bri);
		silofs_assert(!bri->br_rdonly);
	}
}

int silofs_cmi_write_buf(const struct silofs_commit_info *cmi)
{
	return silofs_bri_pwriten(cmi->bri, cmi->off, cmi->buf, cmi->len);
}

void silofs_cmi_increfs(const struct silofs_commit_info *cmi)
{
	for (size_t i = 0; i < cmi->cnt; ++i) {
		silofs_si_incref(cmi->si[i]);
	}
}

void silofs_cmi_decrefs(const struct silofs_commit_info *cmi)
{
	for (size_t i = 0; i < cmi->cnt; ++i) {
		silofs_si_decref(cmi->si[i]);
	}
}

static void cmi_init(struct silofs_commit_info *cmi,
                     const struct silofs_task *task)
{
	list_head_init(&cmi->lh);
	cmi->task = task;
	cmi->bri = NULL;
	cmi->bid.size = 0;
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->buf = NULL;
}

static void cmi_fini(struct silofs_commit_info *cmi)
{
	list_head_fini(&cmi->lh);
	cmi_reset_buf(cmi);
	silofs_cmi_bind_bri(cmi, NULL);
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->task = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	task->t_uber = uber;
}

void silofs_task_fini(struct silofs_task *task)
{
	memset(task, 0xff, sizeof(*task));
	task->t_uber = NULL;
}

void silofs_task_set_creds(struct silofs_task *task,
                           uid_t uid, gid_t gid, pid_t pid)
{
	task->t_oper.op_creds.xcred.uid = uid;
	task->t_oper.op_creds.xcred.gid = gid;
	task->t_oper.op_creds.xcred.pid = pid;
	task->t_oper.op_creds.icred.uid = uid;
	task->t_oper.op_creds.icred.gid = gid;
	task->t_oper.op_creds.icred.pid = pid;
}

void silofs_task_set_umask(struct silofs_task *task, mode_t umask)
{
	task->t_oper.op_creds.xcred.umask = umask;
	task->t_oper.op_creds.icred.umask = umask;
}

void silofs_task_set_ts(struct silofs_task *task, bool rt)
{
	int err;

	err = silofs_ts_gettime(&task->t_oper.op_creds.ts, rt);
	if (err && rt) {
		/* failure in clock_gettime -- fall to non-realtime */
		silofs_ts_gettime(&task->t_oper.op_creds.ts, !rt);
	}
}

int silofs_task_new_commit(const struct silofs_task *task,
                           struct silofs_commit_info **out_cmi)
{
	struct silofs_commit_info *cmi;

	cmi = silofs_allocate(task_alloc(task), sizeof(*cmi));
	if (cmi == NULL) {
		return -ENOMEM;
	}
	cmi_init(cmi, task);
	*out_cmi = cmi;
	return 0;
}

void silofs_task_del_commit(const struct silofs_task *task,
                            struct silofs_commit_info *cmi)
{
	cmi_fini(cmi);
	silofs_deallocate(task_alloc(task), cmi, sizeof(*cmi));
}


struct silofs_alloc *silofs_task_alloc(const struct silofs_task *task)
{
	return task->t_uber->ub_alloc;
}

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task)
{
	return task->t_uber->ub_sbi;
}

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}
