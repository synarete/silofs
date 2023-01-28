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

#define SILOFS_COMMIT_LEN_MAX (2 * SILOFS_MEGA)

static int cmi_setup_buf(struct silofs_commit_info *cmi)
{
	cmi->buf = silofs_allocate(cmi->alloc, cmi->len);
	return unlikely(cmi->buf == NULL) ? -ENOMEM : 0;
}

static void cmi_reset_buf(struct silofs_commit_info *cmi)
{
	if (likely(cmi->buf != NULL)) {
		silofs_deallocate(cmi->alloc, cmi->buf, cmi->len);
	}
	cmi->buf = NULL;
}

static bool cmi_isappendable(const struct silofs_commit_info *cmi,
                             const struct silofs_oaddr *oaddr)
{
	const ssize_t len_max = SILOFS_COMMIT_LEN_MAX;
	size_t len;
	loff_t end;
	loff_t nxt;

	if (cmi->cnt == 0) {
		return true;
	}
	if (cmi->cnt == ARRAY_SIZE(cmi->ref)) {
		return false;
	}
	end = off_end(cmi->off, cmi->len);
	if (oaddr->pos != end) {
		return false;
	}
	len = cmi->len + oaddr->len;
	if (len > (size_t)len_max) {
		return false;
	}
	nxt = off_next(cmi->off, len_max);
	end = off_end(cmi->off, len);
	if (end > nxt) {
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

static void cmi_init(struct silofs_commit_info *cmi,
                     struct silofs_alloc *alloc)
{
	memset(cmi, 0, sizeof(*cmi));
	list_head_init(&cmi->tlh);
	list_head_init(&cmi->cq_lh);
	cmi->alloc = alloc;
	cmi->bri = NULL;
	cmi->bid.size = 0;
	cmi->commit_id = 0;
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->buf = NULL;
	cmi->status = 0;
}

static void cmi_fini(struct silofs_commit_info *cmi)
{
	list_head_fini(&cmi->tlh);
	list_head_fini(&cmi->cq_lh);
	cmi_reset_buf(cmi);
	cmi_unbind_bri(cmi);
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->alloc = NULL;
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

static struct silofs_commit_info *
cmi_from_cq_lh(struct silofs_list_head *cq_lh)
{
	struct silofs_commit_info *cmi = NULL;

	if (cq_lh != NULL) {
		cmi = container_of(cq_lh, struct silofs_commit_info, cq_lh);
	}
	return cmi;
}

static void cmi_apply(struct silofs_commit_info *cmi)
{
	cmi->status = silofs_cmi_write_buf(cmi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int commitq_init(struct silofs_commitq *cq, int indx)
{
	memset(cq, 0, sizeof(*cq));
	cq->cq_index = indx;
	silofs_listq_init(&cq->cq_ls);
	return silofs_mutex_init(&cq->cq_lk);
}

static void commitq_fini(struct silofs_commitq *cq)
{
	silofs_mutex_fini(&cq->cq_lk);
	silofs_listq_fini(&cq->cq_ls);
}

static struct silofs_commit_info *commitq_front_cmi(struct silofs_commitq *cq)
{
	struct silofs_list_head *lh;

	lh = listq_front(&cq->cq_ls);
	return cmi_from_cq_lh(lh);
}

static void commitq_unlink_cmi(struct silofs_commitq *cq,
                               struct silofs_commit_info *cmi)
{
	listq_remove(&cq->cq_ls, &cmi->cq_lh);
}

static void
commitq_push_cmi(struct silofs_commitq *cq, struct silofs_commit_info *cmi)
{
	listq_push_back(&cq->cq_ls, &cmi->cq_lh);
}

static void commitq_enq(struct silofs_commitq *cq,
                        struct silofs_commit_info *cmi)
{
	silofs_mutex_lock(&cq->cq_lk);
	commitq_push_cmi(cq, cmi);
	silofs_mutex_unlock(&cq->cq_lk);
}

static struct silofs_commit_info *
commitq_apply_one_locked(struct silofs_commitq *cq, uint64_t commit_id)
{
	struct silofs_commit_info *cmi;

	cmi = commitq_front_cmi(cq);
	if (cmi == NULL) {
		return NULL;
	}
	if (cmi->commit_id > commit_id) {
		return NULL;
	}
	cmi_apply(cmi);
	commitq_unlink_cmi(cq, cmi);
	return cmi;
}

static struct silofs_commit_info *
commitq_apply_one(struct silofs_commitq *cq, uint64_t commit_id)
{
	struct silofs_commit_info *cmi;

	silofs_mutex_lock(&cq->cq_lk);
	cmi = commitq_apply_one_locked(cq, commit_id);
	silofs_mutex_unlock(&cq->cq_lk);
	return cmi;
}

static int commitq_apply(struct silofs_commitq *cq, uint64_t commit_id)
{
	struct silofs_commit_info *cmi;
	bool apply_more = true;

	while (apply_more) {
		cmi = commitq_apply_one(cq, commit_id);
		apply_more = (cmi != NULL);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int commitqs_init_set(struct silofs_commitqs *cqs)
{
	struct silofs_commitq *cq;
	unsigned int init_cnt = 0;
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(cqs->cqs_set); ++i) {
		cq = &cqs->cqs_set[i];
		err = commitq_init(cq, (int)(i + 1));
		if (err) {
			goto out_err;
		}
		init_cnt++;
	}
	return 0;
out_err:
	for (size_t i = 0; i < init_cnt; ++i) {
		cq = &cqs->cqs_set[i];
		commitq_fini(cq);
	}
	return err;
}

int silofs_commitqs_init(struct silofs_commitqs *cqs,
                         struct silofs_alloc *alloc)
{
	cqs->cqs_alloc = alloc;
	cqs->cqs_apex_cid = 1;
	cqs->cqs_active = 0;
	return commitqs_init_set(cqs);
}

static void commitqs_fini_set(struct silofs_commitqs *cqs)
{
	struct silofs_commitq *cq;

	for (size_t i = 0; i < ARRAY_SIZE(cqs->cqs_set); ++i) {
		cq = &cqs->cqs_set[i];
		commitq_fini(cq);
	}
}

void silofs_commitqs_fini(struct silofs_commitqs *cqs)
{
	commitqs_fini_set(cqs);
	cqs->cqs_alloc = NULL;
}


static struct silofs_commit_info *
commitqs_new_cmi(struct silofs_commitqs *cqs)
{
	struct silofs_commit_info *cmi;

	cmi = silofs_allocate(cqs->cqs_alloc, sizeof(*cmi));
	if (likely(cmi != NULL)) {
		cmi_init(cmi, cqs->cqs_alloc);
		cmi->commit_id = cqs->cqs_apex_cid++;
	}
	return cmi;
}

static void commitqs_del_cmi(struct silofs_commitqs *cqs,
                             struct silofs_commit_info *cmi)
{
	cmi_fini(cmi);
	silofs_deallocate(cqs->cqs_alloc, cmi, sizeof(*cmi));
}

static struct silofs_commitq *
commitqs_sub(struct silofs_commitqs *cqs,
             const struct silofs_commit_info *cmi)
{
	const enum silofs_stype stype = cmi->bid.vspace;
	const size_t idx = stype_isdata(stype) ? 0 : 1;

	return &cqs->cqs_set[idx];
}

void silofs_commitqs_enqueue(struct silofs_commitqs *cqs,
                             struct silofs_commit_info *cmi)
{
	commitq_enq(commitqs_sub(cqs, cmi), cmi);
}

static void commitqs_apply(struct silofs_commitqs *cqs, uint64_t commit_id)
{
	for (size_t i = 0; i < ARRAY_SIZE(cqs->cqs_set); ++i) {
		commitq_apply(&cqs->cqs_set[i], commit_id);
	}
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
	*out_cmi = commitqs_new_cmi(task->t_cqs);
	return likely(*out_cmi != NULL) ? 0 : -ENOMEM;
}

static void task_del_commit(struct silofs_task *task,
                            struct silofs_commit_info *cmi)
{
	cmi_decrefs(cmi);
	cmi_unbind_bri(cmi);
	commitqs_del_cmi(task->t_cqs, cmi);
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

static void task_update_by_commit(struct silofs_task *task,
                                  struct silofs_commit_info *cmi)
{
	if (cmi->commit_id > task->t_apex_cid) {
		task->t_apex_cid = cmi->commit_id;
	}
}

int silofs_task_mk_commit(struct silofs_task *task,
                          struct silofs_commit_info **out_cmi)
{
	struct silofs_commit_info *cmi = NULL;
	int err;

	err = task_new_commit(task, &cmi);
	if (err) {
		return err;
	}
	task_update_by_commit(task, cmi);
	task_push_commit(task, cmi);
	*out_cmi = cmi;
	return 0;
}

static void task_unlink_commit(struct silofs_task *task,
                               struct silofs_commit_info *cmi)
{
	listq_remove(&task->t_pendq, &cmi->tlh);
}

void silofs_task_rm_commit(struct silofs_task *task,
                           struct silofs_commit_info *cmi)
{
	task_unlink_commit(task, cmi);
	task_del_commit(task, cmi);
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

int silofs_task_let_complete(struct silofs_task *task, bool all)
{
	const uint64_t cid = all ? UINT64_MAX : task->t_apex_cid;

	commitqs_apply(task->t_cqs, cid);
	return 0;
}

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task)
{
	return task->t_uber->ub_sbi;
}

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	listq_init(&task->t_pendq);
	task->t_uber = uber;
	task->t_cqs = uber->ub_cqs;
	task->t_apex_cid = 0;
	task->t_interrupt = 0;
	return 0;
}

void silofs_task_fini(struct silofs_task *task)
{
	task_drop_commits(task);
	listq_fini(&task->t_pendq);
	task->t_uber = NULL;
	task->t_cqs = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_num_worker_threads(void)
{
	const long npr = silofs_sc_nproc_onln();
	const long cnt = silofs_clamp32((int)npr, 2, 16);
	const long nth = (((cnt + 1) / 2) * 2);

	return (uint32_t)nth;
}
