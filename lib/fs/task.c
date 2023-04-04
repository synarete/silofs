/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

#define SILOFS_COMMIT_LEN_MAX   (2 * SILOFS_MEGA)
#define SILOFS_CID_ALL          (UINT64_MAX)

static int sqe_setup_buf(struct silofs_submitq_entry *sqe)
{
	sqe->buf = silofs_allocate(sqe->alloc, sqe->len);
	return unlikely(sqe->buf == NULL) ? -ENOMEM : 0;
}

static void sqe_reset_buf(struct silofs_submitq_entry *sqe)
{
	if (likely(sqe->buf != NULL)) {
		silofs_deallocate(sqe->alloc, sqe->buf, sqe->len);
		sqe->buf = NULL;
	}
}

static bool sqe_isappendable(const struct silofs_submitq_entry *sqe,
                             const struct silofs_oaddr *oaddr,
                             const struct silofs_lnode_info *lni)
{
	const ssize_t len_max = SILOFS_COMMIT_LEN_MAX;
	size_t len;
	loff_t end;
	loff_t nxt;

	if (sqe->cnt == 0) {
		return true;
	}
	if (sqe->cnt == ARRAY_SIZE(sqe->ref)) {
		return false;
	}
	if (lni->stype != sqe->ref[0].stype) {
		return false;
	}
	end = off_end(sqe->off, sqe->len);
	if (oaddr->pos != end) {
		return false;
	}
	len = sqe->len + oaddr->len;
	if (len > (size_t)len_max) {
		return false;
	}
	nxt = off_next(sqe->off, len_max);
	end = off_end(sqe->off, len);
	if (end > nxt) {
		return false;
	}
	if (!blobid_isequal(&oaddr->bka.blobid, &sqe->blobid)) {
		return false;
	}
	return true;
}

bool silofs_sqe_append_ref(struct silofs_submitq_entry *sqe,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_lnode_info *lni)
{
	struct silofs_submit_ref *ref;

	silofs_assert_eq(oaddr->len, lni->view_len);

	if (!sqe_isappendable(sqe, oaddr, lni)) {
		return false;
	}
	if (sqe->cnt == 0) {
		blobid_assign(&sqe->blobid, &oaddr->bka.blobid);
		sqe->off = oaddr->pos;
	}
	ref = &sqe->ref[sqe->cnt];
	oaddr_assign(&ref->oaddr, oaddr);
	ref->lbki = lni->lbki;
	ref->view = lni->view;
	ref->stype = lni->stype;
	sqe->len += oaddr->len;
	sqe->cnt += 1;
	return true;
}

static int sqe_encrypt_into_buf(struct silofs_submitq_entry *sqe)
{
	const struct silofs_submit_ref *ref = NULL;
	uint8_t *dst = sqe->buf;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &sqe->ref[i];
		err = silofs_encrypt_view(sqe->uber, &ref->oaddr,
		                          ref->view, dst);
		if (err) {
			return err;
		}
		dst += ref->oaddr.len;
	}
	return 0;
}

int silofs_sqe_assign_buf(struct silofs_submitq_entry *sqe)
{
	int err;

	err = sqe_setup_buf(sqe);
	if (err) {
		return err;
	}
	err = sqe_encrypt_into_buf(sqe);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_sqe_bind_blobf(struct silofs_submitq_entry *sqe,
                           struct silofs_blobf *blobf)
{
	if (sqe->blobf != NULL) {
		blobf_decref(sqe->blobf);
		sqe->blobf = NULL;
	}
	if (blobf != NULL) {
		sqe->blobf = blobf;
		blobf_incref(sqe->blobf);
		silofs_assert(!blobf->b_rdonly);
	}
}

static void sqe_unbind_blobf(struct silofs_submitq_entry *sqe)
{
	silofs_sqe_bind_blobf(sqe, NULL);
}

static int sqe_pwrite_buf(const struct silofs_submitq_entry *sqe)
{
	return silofs_blobf_pwriten(sqe->blobf, sqe->off,
	                            sqe->buf, sqe->len, true);
}

void silofs_sqe_increfs(struct silofs_submitq_entry *sqe)
{
	struct silofs_submit_ref *ref;

	if (!sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			ref = &sqe->ref[i];
			silofs_lbki_incref(ref->lbki);
		}
		sqe->hold_refs = 1;
	}
}

static void sqe_decrefs(struct silofs_submitq_entry *sqe)
{
	struct silofs_submit_ref *ref;

	if (sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			ref = &sqe->ref[i];
			silofs_lbki_decref(ref->lbki);
		}
		sqe->hold_refs = 0;
	}
}

static void sqe_init(struct silofs_submitq_entry *sqe,
                     struct silofs_alloc *alloc, uint64_t uniq_id)
{
	memset(sqe, 0, sizeof(*sqe));
	list_head_init(&sqe->qlh);
	sqe->alloc = alloc;
	sqe->uber = NULL;
	sqe->blobf = NULL;
	sqe->blobid.size = 0;
	sqe->uniq_id = uniq_id;
	sqe->off = -1;
	sqe->len = 0;
	sqe->cnt = 0;
	sqe->buf = NULL;
	sqe->hold_refs = 0;
	sqe->status = 0;
}

static void sqe_fini(struct silofs_submitq_entry *sqe)
{
	list_head_fini(&sqe->qlh);
	sqe_reset_buf(sqe);
	sqe_unbind_blobf(sqe);
	sqe->off = -1;
	sqe->len = 0;
	sqe->cnt = 0;
	sqe->alloc = NULL;
	sqe->status = -1;
}

static struct silofs_submitq_entry *
sqe_new(struct silofs_alloc *alloc, uint64_t uniq_id)
{
	struct silofs_submitq_entry *sqe;

	sqe = silofs_allocate(alloc, sizeof(*sqe));
	if (likely(sqe != NULL)) {
		sqe_init(sqe, alloc, uniq_id);
	}
	return sqe;
}

static void sqe_del(struct silofs_submitq_entry *sqe,
                    struct silofs_alloc *alloc)
{
	sqe_fini(sqe);
	silofs_deallocate(alloc, sqe, sizeof(*sqe));
}

static struct silofs_submitq_entry *sqe_from_qlh(struct silofs_list_head *qlh)
{
	struct silofs_submitq_entry *sqe = NULL;

	if (qlh != NULL) {
		sqe = container_of(qlh, struct silofs_submitq_entry, qlh);
	}
	return sqe;
}

static int sqe_apply(struct silofs_submitq_entry *sqe)
{
	sqe->status = sqe_pwrite_buf(sqe);
	return sqe->status;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_submitq_init(struct silofs_submitq *smq, struct silofs_alloc *alloc)
{
	memset(smq, 0, sizeof(*smq));
	silofs_listq_init(&smq->smq_listq);
	smq->smq_alloc = alloc;
	smq->smq_apex_id = 1;
	return silofs_mutex_init(&smq->smq_mutex);
}

void silofs_submitq_fini(struct silofs_submitq *smq)
{
	silofs_mutex_fini(&smq->smq_mutex);
	silofs_listq_fini(&smq->smq_listq);
	smq->smq_apex_id = 0;
}

static struct silofs_submitq_entry *
submitq_front_sqe(struct silofs_submitq *smq)
{
	struct silofs_list_head *lh;

	lh = listq_front(&smq->smq_listq);
	return sqe_from_qlh(lh);
}

static void submitq_unlink_sqe(struct silofs_submitq *smq,
                               struct silofs_submitq_entry *sqe)
{
	listq_remove(&smq->smq_listq, &sqe->qlh);
}

static void submitq_push_sqe(struct silofs_submitq *smq,
                             struct silofs_submitq_entry *sqe)
{
	listq_push_back(&smq->smq_listq, &sqe->qlh);
}

void silofs_submitq_enqueue(struct silofs_submitq *smq,
                            struct silofs_submitq_entry *sqe)
{
	silofs_mutex_lock(&smq->smq_mutex);
	submitq_push_sqe(smq, sqe);
	silofs_mutex_unlock(&smq->smq_mutex);
}

static struct silofs_submitq_entry *
submitq_get_sqe(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_entry *sqe;

	sqe = submitq_front_sqe(smq);
	if (sqe == NULL) {
		return NULL;
	}
	if (sqe->uniq_id > id) {
		return NULL;
	}
	return sqe;
}

static int submitq_apply_one(struct silofs_submitq *smq, uint64_t id,
                             struct silofs_submitq_entry **out_sqe)
{
	struct silofs_submitq_entry *sqe;
	int err = -ENOENT;

	*out_sqe = NULL;
	silofs_mutex_lock(&smq->smq_mutex);
	sqe = submitq_get_sqe(smq, id);
	if (sqe != NULL) {
		submitq_unlink_sqe(smq, sqe);
		err = sqe_apply(sqe);
	}
	silofs_mutex_unlock(&smq->smq_mutex);
	*out_sqe = sqe;
	return err;
}

static int submitq_apply(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_entry *sqe = NULL;
	int err = 0;

	while (!err) {
		err = submitq_apply_one(smq, id, &sqe);
		if (sqe != NULL) {
			silofs_submitq_del_sqe(smq, sqe);
		}
	}
	return err;
}

int silofs_submitq_new_sqe(struct silofs_submitq *smq,
                           struct silofs_submitq_entry **out_sqe)
{
	*out_sqe = sqe_new(smq->smq_alloc, smq->smq_apex_id++);
	return likely(*out_sqe != NULL) ? 0 : -ENOMEM;
}

void silofs_submitq_del_sqe(struct silofs_submitq *smq,
                            struct silofs_submitq_entry *sqe)
{
	sqe_decrefs(sqe);
	sqe_reset_buf(sqe);
	sqe_unbind_blobf(sqe);
	sqe_del(sqe, smq->smq_alloc);
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

void silofs_task_update_by(struct silofs_task *task,
                           struct silofs_submitq_entry *sqe)
{
	if (sqe->uniq_id > task->t_apex_id) {
		task->t_apex_id = sqe->uniq_id;
	}
}

int silofs_task_submit(struct silofs_task *task, bool all)
{
	int err = 0;

	if (all) {
		err = submitq_apply(task->t_submitq, SILOFS_CID_ALL);
	} else if (task->t_apex_id) {
		err = submitq_apply(task->t_submitq, task->t_apex_id);
	}
	return (err == -ENOENT) ? 0 : err;
}

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task)
{
	return task->t_uber->ub_sbi;
}

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	task->t_uber = uber;
	task->t_submitq = uber->ub.submitq;
	task->t_apex_id = 0;
	task->t_interrupt = 0;
	task->t_may_flush = 0;
	return 0;
}

void silofs_task_fini(struct silofs_task *task)
{
	task->t_uber = NULL;
	task->t_submitq = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_num_worker_threads(void)
{
	const long npr = silofs_sc_nproc_onln();
	const long cnt = silofs_clamp32((int)npr, 2, 16);
	const long nth = (((cnt + 1) / 2) * 2);

	return (uint32_t)nth;
}
