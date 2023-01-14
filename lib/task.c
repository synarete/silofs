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

/* local functions */
static struct silofs_alloc *task_alloc(const struct silofs_task *task);


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
	if (cmi->cnt == ARRAY_SIZE(cmi->ref)) {
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
	struct silofs_commit_ref *ref;

	if (!cmi_isappendable(cmi, oaddr)) {
		return false;
	}
	if (cmi->cnt == 0) {
		blobid_assign(&cmi->bid, &oaddr->bka.blobid);
		cmi->off = oaddr->pos;
	}
	ref = &cmi->ref[cmi->cnt];
	ref->bki = silofs_bki_of(si);
	ref->view = si->s_view;
	ref->len = si->s_view_len;
	cmi->len += ref->len;
	cmi->cnt += 1;
	return true;
}

int silofs_cmi_assign_buf(struct silofs_commit_info *cmi)
{
	const struct silofs_commit_ref *ref;
	uint8_t *dst = NULL;
	int err;

	err = cmi_setup_buf(cmi);
	if (err) {
		return err;
	}
	dst = cmi->buf;
	for (size_t i = 0; i < cmi->cnt; ++i) {
		ref = &cmi->ref[i];
		memcpy(dst, ref->view, ref->len);
		dst += ref->len;
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

static void cmi_unbind_bri(struct silofs_commit_info *cmi)
{
	silofs_cmi_bind_bri(cmi, NULL);
}

int silofs_cmi_write_buf(const struct silofs_commit_info *cmi)
{
	return silofs_bri_pwriten(cmi->bri, cmi->off, cmi->buf, cmi->len);
}

void silofs_cmi_increfs(struct silofs_commit_info *cmi)
{
	struct silofs_commit_ref *ref;

	for (size_t i = 0; i < cmi->cnt; ++i) {
		ref = &cmi->ref[i];
		silofs_bki_incref(ref->bki);
	}
}

static void cmi_decrefs(struct silofs_commit_info *cmi)
{
	struct silofs_commit_ref *ref;

	for (size_t i = 0; i < cmi->cnt; ++i) {
		ref = &cmi->ref[i];
		silofs_bki_decref(ref->bki);
	}
}

static void cmi_init(struct silofs_commit_info *cmi, struct silofs_task *task)
{
	memset(cmi, 0, sizeof(*cmi));
	list_head_init(&cmi->tlh);
	cmi->task = task;
	cmi->bri = NULL;
	cmi->bid.size = 0;
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->buf = NULL;
	cmi->status = 0;
	cmi->done = false;
}

static void cmi_fini(struct silofs_commit_info *cmi)
{
	list_head_fini(&cmi->tlh);
	cmi_reset_buf(cmi);
	cmi_unbind_bri(cmi);
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->task = NULL;
	cmi->status = -1;
}

static struct silofs_commit_info *cmi_from_tlh(struct silofs_list_head *tlh)
{
	struct silofs_commit_info *cmi = NULL;

	if (tlh != NULL) {
		cmi = container_of(tlh, struct silofs_commit_info, tlh);
	}
	return cmi;
}

static struct silofs_commit_info *cmi_new(struct silofs_task *task)
{
	struct silofs_commit_info *cmi;
	struct silofs_alloc *alloc = task_alloc(task);

	cmi = silofs_allocate(alloc, sizeof(*cmi));
	if (likely(cmi != NULL)) {
		cmi_init(cmi, task);
	}
	return cmi;
}

static void cmi_del(struct silofs_commit_info *cmi)
{
	struct silofs_alloc *alloc = task_alloc(cmi->task);

	cmi_fini(cmi);
	silofs_deallocate(alloc, cmi, sizeof(*cmi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static int task_new_commit(struct silofs_task *task,
                           struct silofs_commit_info **out_cmi)
{
	*out_cmi = cmi_new(task);
	return likely(*out_cmi != NULL) ? 0 : -ENOMEM;
}

static void task_del_commit(struct silofs_task *task,
                            struct silofs_commit_info *cmi)
{
	silofs_assert_eq(task, cmi->task);
	cmi_decrefs(cmi);
	cmi_unbind_bri(cmi);
	cmi_del(cmi);
}

static void task_push_commit(struct silofs_task *task,
                             struct silofs_commit_info *cmi)
{
	listq_push_back(&task->t_pendq, &cmi->tlh);
}

static struct silofs_commit_info *task_pop_commit(struct silofs_task *task)
{
	struct silofs_list_head *tlh;

	tlh = listq_pop_front(&task->t_pendq);
	return cmi_from_tlh(tlh);
}

int silofs_task_make_commit(struct silofs_task *task,
                            struct silofs_commit_info **out_cmi)
{
	struct silofs_commit_info *cmi = NULL;
	int err;

	err = task_new_commit(task, &cmi);
	if (err) {
		return err;
	}
	task_push_commit(task, cmi);
	*out_cmi = cmi;
	return 0;
}

static int task_wait_commits(struct silofs_task *task)
{
	struct silofs_list_head *itr = NULL;
	struct silofs_commit_info *cmi = NULL;
	struct silofs_listq *pendq = &task->t_pendq;
	int ret = 0;

	itr = listq_front(pendq);
	while (itr != NULL) {
		cmi = cmi_from_tlh(itr);
		if (!cmi->done) {
			/* XXX TODO */
		}
		if (!ret && cmi->status) {
			ret = cmi->status;
		}
		itr = listq_next(pendq, itr);
	}
	return ret;
}

static void task_drop_commits(struct silofs_task *task)
{
	struct silofs_commit_info *cmi;

	cmi = task_pop_commit(task);
	while (cmi != NULL) {
		task_del_commit(task, cmi);
		cmi = task_pop_commit(task);
	}
}

int silofs_task_let_complete(struct silofs_task *task)
{
	int err;

	err = task_wait_commits(task);
	task_drop_commits(task);
	return err;
}

static struct silofs_alloc *task_alloc(const struct silofs_task *task)
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

void silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	listq_init(&task->t_pendq);
	task->t_uber = uber;
}

void silofs_task_fini(struct silofs_task *task)
{
	task_drop_commits(task);
	listq_fini(&task->t_pendq);
	task->t_uber = NULL;
}

