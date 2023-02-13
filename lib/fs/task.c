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
                             const struct silofs_oaddr *oaddr)
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
                           struct silofs_snode_info *si)
{
	struct silofs_submit_ref *ref;

	if (!sqe_isappendable(sqe, oaddr)) {
		return false;
	}
	if (sqe->cnt == 0) {
		blobid_assign(&sqe->blobid, &oaddr->bka.blobid);
		sqe->off = oaddr->pos;
	}
	ref = &sqe->ref[sqe->cnt];
	ref->bki = silofs_bki_of(si);
	ref->view = si->s_view;
	ref->len = si->s_view_len;
	sqe->len += ref->len;
	sqe->cnt += 1;
	return true;
}

int silofs_sqe_assign_buf(struct silofs_submitq_entry *sqe)
{
	const struct silofs_submit_ref *ref;
	uint8_t *dst = NULL;
	int err;

	err = sqe_setup_buf(sqe);
	if (err) {
		return err;
	}
	dst = sqe->buf;
	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &sqe->ref[i];
		memcpy(dst, ref->view, ref->len);
		dst += ref->len;
	}
	return 0;
}

void silofs_sqe_bind_bri(struct silofs_submitq_entry *sqe,
                         struct silofs_blobref_info *bri)
{
	if (sqe->bri != NULL) {
		bri_decref(sqe->bri);
		sqe->bri = NULL;
	}
	if (bri != NULL) {
		sqe->bri = bri;
		bri_incref(sqe->bri);
		silofs_assert(!bri->br_rdonly);
	}
}

static void sqe_unbind_bri(struct silofs_submitq_entry *sqe)
{
	silofs_sqe_bind_bri(sqe, NULL);
}

static int sqe_pwrite_buf(const struct silofs_submitq_entry *sqe)
{
	return silofs_bri_pwriten(sqe->bri, sqe->off,
	                          sqe->buf, sqe->len, true);
}

void silofs_sqe_increfs(struct silofs_submitq_entry *sqe)
{
	struct silofs_submit_ref *ref;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &sqe->ref[i];
		silofs_bki_incref(ref->bki);
	}
}

static void sqe_decrefs(struct silofs_submitq_entry *sqe)
{
	struct silofs_submit_ref *ref;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &sqe->ref[i];
		silofs_bki_decref(ref->bki);
	}
}

static int sqe_init(struct silofs_submitq_entry *sqe,
                    struct silofs_alloc *alloc, uint64_t uniq_id)
{
	memset(sqe, 0, sizeof(*sqe));
	list_head_init(&sqe->qlh);
	list_head_init(&sqe->tlh);
	sqe->alloc = alloc;
	sqe->task = NULL;
	sqe->bri = NULL;
	sqe->blobid.size = 0;
	sqe->uniq_id = uniq_id;
	sqe->off = -1;
	sqe->len = 0;
	sqe->cnt = 0;
	sqe->buf = NULL;
	sqe->status = 0;
	return silofs_mutex_init(&sqe->mu);
}

static void sqe_fini(struct silofs_submitq_entry *sqe)
{
	silofs_mutex_fini(&sqe->mu);
	list_head_fini(&sqe->qlh);
	list_head_fini(&sqe->tlh);
	sqe_reset_buf(sqe);
	sqe_unbind_bri(sqe);
	sqe->off = -1;
	sqe->len = 0;
	sqe->cnt = 0;
	sqe->alloc = NULL;
	sqe->status = -1;
}

static struct silofs_submitq_entry *sqe_from_tlh(struct silofs_list_head *tlh)
{
	struct silofs_submitq_entry *sqe = NULL;

	if (tlh != NULL) {
		sqe = container_of(tlh, struct silofs_submitq_entry, tlh);
	}
	return sqe;
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

static void sqe_lock(struct silofs_submitq_entry *sqe)
{
	silofs_mutex_lock(&sqe->mu);
}

static void sqe_unlock(struct silofs_submitq_entry *sqe)
{
	silofs_mutex_unlock(&sqe->mu);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_submitq_init(struct silofs_submitq *smq)
{
	memset(smq, 0, sizeof(*smq));
	silofs_listq_init(&smq->smq_listq);
	smq->smq_apex_id = 1;
	return silofs_mutex_init(&smq->smq_mutex);
}

void silofs_submitq_fini(struct silofs_submitq *smq)
{
	silofs_mutex_fini(&smq->smq_mutex);
	silofs_listq_fini(&smq->smq_listq);
	smq->smq_apex_id = 0;
}

static struct silofs_submitq_entry *submitq_front_sqe(struct silofs_submitq
                *smq)
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

static void submitq_enqueue(struct silofs_submitq *smq,
                            struct silofs_submitq_entry *sqe)
{
	silofs_mutex_lock(&smq->smq_mutex);
	submitq_push_sqe(smq, sqe);
	silofs_mutex_unlock(&smq->smq_mutex);
}

static struct silofs_submitq_entry *
submitq_get_locked_sqe(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_entry *sqe;

	sqe = submitq_front_sqe(smq);
	if (sqe == NULL) {
		return NULL;
	}
	if (sqe->uniq_id > id) {
		return NULL;
	}
	sqe_lock(sqe);
	return sqe;
}

static struct silofs_submitq_entry *
submitq_dequeue_locked_sqe(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_entry *sqe;

	silofs_mutex_lock(&smq->smq_mutex);
	sqe = submitq_get_locked_sqe(smq, id);
	if (sqe != NULL) {
		submitq_unlink_sqe(smq, sqe);
	}
	silofs_mutex_unlock(&smq->smq_mutex);
	return sqe;
}

static int submitq_apply(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_entry *sqe;
	int ret = 0;
	int err;

	sqe = submitq_dequeue_locked_sqe(smq, id);
	while (sqe != NULL) {
		err = sqe_apply(sqe);
		if (err && !ret) {
			ret = err;
		}
		sqe_unlock(sqe);
		sqe = submitq_dequeue_locked_sqe(smq, id);
	}
	return ret;
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

static int task_new_sqe(struct silofs_task *task,
                        struct silofs_submitq_entry **out_sqe)
{
	struct silofs_alloc *alloc = task->t_uber->ub_alloc;
	struct silofs_submitq_entry *sqe;
	int err;

	sqe = silofs_allocate(alloc, sizeof(*sqe));
	if (unlikely(sqe == NULL)) {
		return -ENOMEM;
	}
	err = sqe_init(sqe, alloc, task->t_submitq->smq_apex_id++);
	if (err) {
		silofs_deallocate(alloc, sqe, sizeof(*sqe));
		return err;
	}
	*out_sqe = sqe;
	return 0;
}

static void task_del_sqe(struct silofs_task *task,
                         struct silofs_submitq_entry *sqe)
{
	struct silofs_alloc *alloc = task->t_uber->ub_alloc;

	sqe_fini(sqe);
	silofs_deallocate(alloc, sqe, sizeof(*sqe));
}

static void task_link_sqe(struct silofs_task *task,
                          struct silofs_submitq_entry *sqe)
{
	listq_push_back(&task->t_pendq, &sqe->tlh);
	sqe->task = task;
}

static void task_unlink_sqe(struct silofs_task *task,
                            struct silofs_submitq_entry *sqe)
{
	if (sqe->task == task) {
		listq_remove(&task->t_pendq, &sqe->tlh);
		sqe->task = NULL;
	}
}

static struct silofs_submitq_entry *task_front_sqe(struct silofs_task *task)
{
	struct silofs_list_head *tlh;

	tlh = listq_front(&task->t_pendq);
	return sqe_from_tlh(tlh);
}

static void task_update_by(struct silofs_task *task,
                           struct silofs_submitq_entry *sqe)
{
	if (sqe->uniq_id > task->t_apex_id) {
		task->t_apex_id = sqe->uniq_id;
	}
}

int silofs_task_mk_sqe(struct silofs_task *task,
                       struct silofs_submitq_entry **out_sqe)
{
	struct silofs_submitq_entry *sqe = NULL;
	int err;

	err = task_new_sqe(task, &sqe);
	if (err) {
		return err;
	}
	task_update_by(task, sqe);
	task_link_sqe(task, sqe);
	*out_sqe = sqe;
	return 0;
}

static void task_remove_sqe(struct silofs_task *task,
                            struct silofs_submitq_entry *sqe)
{
	sqe_lock(sqe);
	sqe_decrefs(sqe);
	sqe_reset_buf(sqe);
	sqe_unbind_bri(sqe);
	sqe_unlock(sqe);
	task_unlink_sqe(task, sqe);
}

static void task_remove_del_sqe(struct silofs_task *task,
                                struct silofs_submitq_entry *sqe)
{
	task_remove_sqe(task, sqe);
	task_del_sqe(task, sqe);
}

void silofs_task_rm_sqe(struct silofs_task *task,
                        struct silofs_submitq_entry *sqe)
{
	task_remove_del_sqe(task, sqe);
}

void silofs_task_enq_sqe(struct silofs_task *task,
                         struct silofs_submitq_entry *sqe)
{
	submitq_enqueue(task->t_submitq, sqe);
}

int silofs_task_submit(struct silofs_task *task, bool all)
{
	int ret = 0;

	if (all) {
		ret = submitq_apply(task->t_submitq, SILOFS_CID_ALL);
	} else if (task->t_apex_id) {
		ret = submitq_apply(task->t_submitq, task->t_apex_id);
	}
	return ret;
}

static int task_drop_sqes(struct silofs_task *task)
{
	struct silofs_submitq_entry *sqe;
	int ret = 0;

	sqe = task_front_sqe(task);
	while (sqe != NULL) {
		if (sqe->status && (ret == 0)) {
			ret = sqe->status;
		}
		task_remove_del_sqe(task, sqe);
		sqe = task_front_sqe(task);
	}
	return ret;
}

int silofs_task_complete(struct silofs_task *task)
{
	task->t_may_flush = 0;
	return task_drop_sqes(task);
}

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task)
{
	return task->t_uber->ub_sbi;
}

bool silofs_task_has_kcopy(const struct silofs_task *task)
{
	const struct silofs_sb_info *sbi = silofs_task_sbi(task);

	return (sbi != NULL) && ((sbi->sb_ctl_flags & SILOFS_SBCF_KCOPY) > 0);
}

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	listq_init(&task->t_pendq);
	task->t_uber = uber;
	task->t_submitq = uber->ub_submitq;
	task->t_apex_id = 0;
	task->t_interrupt = 0;
	task->t_may_flush = 0;
	return 0;
}

void silofs_task_fini(struct silofs_task *task)
{
	task_drop_sqes(task);
	listq_fini(&task->t_pendq);
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
