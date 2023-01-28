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

/* local functions */
static struct silofs_alloc *task_alloc(const struct silofs_task *task);
static void task_signal_done(struct silofs_task *task,
                             struct silofs_commit_info *cmi);
static int commitq_execute(struct silofs_commitq *cq);


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

static void cmi_init(struct silofs_commit_info *cmi, struct silofs_task *task)
{
	memset(cmi, 0, sizeof(*cmi));
	list_head_init(&cmi->tlh);
	list_head_init(&cmi->flh);
	cmi->task = task;
	cmi->bri = NULL;
	cmi->bid.size = 0;
	cmi->commit_id = 0;
	cmi->off = -1;
	cmi->len = 0;
	cmi->cnt = 0;
	cmi->buf = NULL;
	cmi->status = 0;
	cmi->async = 0;
	cmi->done = 0;
}

static void cmi_fini(struct silofs_commit_info *cmi)
{
	list_head_fini(&cmi->tlh);
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

static struct silofs_commit_info *cmi_from_flh(struct silofs_list_head *flh)
{
	struct silofs_commit_info *cmi = NULL;

	if (flh != NULL) {
		cmi = container_of(flh, struct silofs_commit_info, flh);
	}
	return cmi;
}

static void cmi_execute_and_signal(struct silofs_commit_info *cmi)
{
	cmi->status = silofs_cmi_write_buf(cmi);
	task_signal_done(cmi->task, cmi);
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

static void task_unlink_commit(struct silofs_task *task,
                               struct silofs_commit_info *cmi)
{
	listq_remove(&task->t_pendq, &cmi->tlh);
}

static void task_set_commit_id(struct silofs_task *task,
                               struct silofs_commit_info *cmi)
{
	cmi->commit_id = ++(task->t_uber->ub_commit_id);
	if (likely(cmi->commit_id > task->t_apex_cid)) {
		task->t_apex_cid = cmi->commit_id;
	}
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
	task_set_commit_id(task, cmi);
	task_push_commit(task, cmi);
	*out_cmi = cmi;
	return 0;
}

static void task_signal_done(struct silofs_task *task,
                             struct silofs_commit_info *cmi)
{
	struct silofs_lock *lock = &task->t_lock;

	silofs_mutex_lock(&lock->mu);
	cmi->done = 1;
	silofs_cond_signal(&lock->co);
	silofs_mutex_unlock(&lock->mu);
}

static bool task_wait_commit(struct silofs_task *task,
                             struct silofs_commit_info *cmi)
{
	struct silofs_lock *lock = &task->t_lock;
	bool done = false;
	int err = 0;

	silofs_mutex_lock(&lock->mu);
	done = (cmi->done > 0);
	if (cmi->async && !done) {
		err = silofs_cond_ntimedwait(&lock->co, &lock->mu, 1);
		if (!err) {
			done = (cmi->done > 0);
		}
	}
	silofs_mutex_unlock(&lock->mu);
	return done;
}

static int task_wait_commits(struct silofs_task *task)
{
	struct silofs_list_head *itr = NULL;
	struct silofs_commit_info *cmi = NULL;
	struct silofs_listq *pendq = &task->t_pendq;
	int ret = 0;
	bool done;

	itr = listq_front(pendq);
	while (itr != NULL) {
		cmi = cmi_from_tlh(itr);
		done = task_wait_commit(task, cmi);
		if (!done) {
			continue;
		}
		if (!ret && cmi->status) {
			ret = cmi->status;
		}
		task_unlink_commit(task, cmi);
		task_del_commit(task, cmi);

		itr = listq_front(pendq);
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

int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	listq_init(&task->t_pendq);
	task->t_uber = uber;
	task->t_apex_cid = 0;
	task->t_interrupt = 0;
	return silofs_lock_init(&task->t_lock);
}

void silofs_task_fini(struct silofs_task *task)
{
	task_drop_commits(task);
	listq_fini(&task->t_pendq);
	silofs_lock_fini(&task->t_lock);
	task->t_uber = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int commitq_init(struct silofs_commitq *cq, int indx)
{
	memset(cq, 0, sizeof(*cq));
	cq->cq_active = 0;
	cq->cq_index = indx;
	silofs_listq_init(&cq->cq_ls);
	return silofs_lock_init(&cq->cq_lk);
}

static void commitq_fini(struct silofs_commitq *cq)
{
	silofs_lock_fini(&cq->cq_lk);
	silofs_listq_fini(&cq->cq_ls);
}

static int commitq_do_start(struct silofs_thread *th)
{
	struct silofs_commitq *cq = th->arg;
	int err;

	log_info("start commitq worker: %s", th->name);
	err = commitq_execute(cq);
	log_info("finish commitq worker: %s", th->name);
	return err;
}

static void commitq_reset_th(struct silofs_commitq *cq)
{
	struct silofs_thread *th = &cq->cq_th;

	silofs_memzero(th, sizeof(*th));
}

static void commitq_make_thread_name(const struct silofs_commitq *cq,
                                     char *name_buf, size_t name_bsz)
{
	snprintf(name_buf, name_bsz, "silofs-cq%d", cq->cq_index);
}

static int commitq_start(struct silofs_commitq *cq)
{
	char name[32] = "";
	struct silofs_thread *th = &cq->cq_th;
	int ret = 0;

	if (!cq->cq_active) {
		cq->cq_active = 1;
		commitq_reset_th(cq);
		commitq_make_thread_name(cq, name, sizeof(name) - 1);
		ret = silofs_thread_create(th, commitq_do_start, cq, name);
	}
	return ret;
}

static int commitq_stop(struct silofs_commitq *cq)
{
	int ret = 0;

	if (cq->cq_active) {
		cq->cq_active = 0;
		ret = silofs_thread_join(&cq->cq_th);
		silofs_assert_eq(cq->cq_ls.sz, 0);
		commitq_reset_th(cq);
	}
	return ret;
}

static struct silofs_commit_info *
commitq_pop_cmi(struct silofs_commitq *cq)
{
	struct silofs_list_head *lh;

	lh = listq_pop_front(&cq->cq_ls);
	return cmi_from_flh(lh);
}

static void
commitq_push_cmi(struct silofs_commitq *cq, struct silofs_commit_info *cmi)
{
	listq_push_back(&cq->cq_ls, &cmi->flh);
}

static void commitq_enq(struct silofs_commitq *cq,
                        struct silofs_commit_info *cmi)
{
	struct silofs_lock *lock = &cq->cq_lk;

	cmi->async = 1;
	silofs_mutex_lock(&lock->mu);
	commitq_push_cmi(cq, cmi);
	silofs_cond_signal(&lock->co);
	silofs_mutex_unlock(&lock->mu);
}

static struct silofs_commit_info *commitq_deq(struct silofs_commitq *cq)
{
	struct silofs_commit_info *cmi = NULL;
	struct silofs_lock *lock = &cq->cq_lk;
	int err;

	silofs_mutex_lock(&lock->mu);
	cmi = commitq_pop_cmi(cq);
	if (cmi == NULL) {
		err = silofs_cond_ntimedwait(&lock->co, &lock->mu, 1);
		if (!err) {
			cmi = commitq_pop_cmi(cq);
		}
	}
	silofs_mutex_unlock(&lock->mu);
	return cmi;
}

static int commitq_execute(struct silofs_commitq *cq)
{
	struct silofs_commit_info *cmi;

	while (cq->cq_active) {
		cmi = commitq_deq(cq);
		if (cmi != NULL) {
			cmi_execute_and_signal(cmi);
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int commitqs_init_set(struct silofs_commitqs *cqs, unsigned int cnt)
{
	struct silofs_commitq *cq;
	struct silofs_commitq *cq_arr;
	unsigned int init_cnt = 0;
	int err;

	cq_arr = silofs_allocate(cqs->cqs_alloc, cnt * sizeof(*cq));
	if (cq_arr == NULL) {
		return -ENOMEM;
	}
	for (size_t i = 0; i < cnt; ++i) {
		cq = &cq_arr[i];
		err = commitq_init(cq, (int)(i + 1));
		if (err) {
			goto out_err;
		}
		init_cnt++;
	}
	cqs->cqs_set = cq_arr;
	cqs->cqs_count = init_cnt;
	return 0;
out_err:
	for (size_t i = 0; i < init_cnt; ++i) {
		cq = &cq_arr[i];
		commitq_fini(cq);
	}
	silofs_deallocate(cqs->cqs_alloc, cq_arr, cnt * sizeof(*cq));
	return err;
}

static uint32_t commitqs_nworkers(void)
{
	const uint32_t nworkers = silofs_num_worker_threads();

	return (nworkers > 2) ? (nworkers / 2) : 1;
}

int silofs_commitqs_init(struct silofs_commitqs *cqs,
                         struct silofs_alloc *alloc)
{
	cqs->cqs_alloc = alloc;
	cqs->cqs_set = NULL;
	cqs->cqs_count = 0;
	cqs->cqs_active = 0;
	return commitqs_init_set(cqs, commitqs_nworkers());
}

static void commitqs_fini_set(struct silofs_commitqs *cqs)
{
	struct silofs_commitq *cq;

	for (size_t i = 0; i < cqs->cqs_count; ++i) {
		cq = &cqs->cqs_set[i];
		commitq_fini(cq);
	}
	silofs_deallocate(cqs->cqs_alloc, cqs->cqs_set,
	                  cqs->cqs_count * sizeof(*cq));
	cqs->cqs_set = NULL;
	cqs->cqs_count = 0;
}

void silofs_commitqs_fini(struct silofs_commitqs *cqs)
{
	commitqs_fini_set(cqs);
	cqs->cqs_alloc = NULL;
}

int silofs_commitqs_start(struct silofs_commitqs *cqs)
{
	struct silofs_commitq *cq;
	unsigned int start_cnt = 0;
	int err;

	for (size_t i = 0; i < cqs->cqs_count; ++i) {
		cq = &cqs->cqs_set[i];
		err = commitq_start(cq);
		if (err) {
			goto out_err;
		}
		start_cnt++;
	}
	cqs->cqs_active = 1;
	return 0;

out_err:
	for (size_t i = 0; i < start_cnt; ++i) {
		cq = &cqs->cqs_set[i];
		commitq_stop(cq);
	}
	return err;
}

int silofs_commitqs_stop(struct silofs_commitqs *cqs)
{
	struct silofs_commitq *cq;
	int ret = 0;
	int err;

	cqs->cqs_active = 0;
	for (size_t i = 0; i < cqs->cqs_count; ++i) {
		cq = &cqs->cqs_set[i];
		err = commitq_stop(cq);
		if (err && (ret == 0)) {
			ret = err;
		}
	}
	return ret;
}

static struct silofs_commitq *
commitqs_sub(const struct silofs_commitqs *cqs,
             const struct silofs_commit_info *cmi)
{
	const ssize_t len_max = SILOFS_COMMIT_LEN_MAX;
	const ssize_t seg = cmi->off / len_max;
	const size_t idx = (size_t)seg % cqs->cqs_count;

	return &cqs->cqs_set[idx];
}

void silofs_commitqs_enqueue(struct silofs_commitqs *cqs,
                             struct silofs_commit_info *cmi)
{
	commitq_enq(commitqs_sub(cqs, cmi), cmi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_num_worker_threads(void)
{
	const long npr = silofs_sc_nproc_onln();
	const long cnt = silofs_clamp32((int)npr, 2, 16);
	const long nth = (((cnt + 1) / 2) * 2);

	return (uint32_t)nth;
}
