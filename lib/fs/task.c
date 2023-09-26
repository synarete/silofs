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

static int sqe_setup_iov_at(struct silofs_submitq_ent *sqe,
                            size_t idx, size_t len)
{
	silofs_assert_lt(idx, ARRAY_SIZE(sqe->iov));
	silofs_assert_null(sqe->iov[idx].iov_base);

	sqe->iov[idx].iov_base = silofs_allocate(sqe->alloc, len, 0);
	if (sqe->iov[idx].iov_base == NULL) {
		return -SILOFS_ENOMEM;
	}
	sqe->iov[idx].iov_len = len;
	return 0;
}

static void sqe_reset_iovs(struct silofs_submitq_ent *sqe)
{
	for (size_t idx = 0; idx < sqe->cnt; ++idx) {
		silofs_deallocate(sqe->alloc, sqe->iov[idx].iov_base,
		                  sqe->iov[idx].iov_len, 0);
		sqe->iov[idx].iov_base = NULL;
		sqe->iov[idx].iov_len = 0;
	}
}

static bool sqe_isappendable(const struct silofs_submitq_ent *sqe,
                             const struct silofs_paddr *paddr,
                             const struct silofs_lnode_info *lni)
{
	const ssize_t len_max = SILOFS_COMMIT_LEN_MAX;
	size_t len;
	loff_t end;
	loff_t nxt;

	if (sqe->cnt == 0) {
		return true;
	}
	if (sqe->cnt == ARRAY_SIZE(sqe->lbki)) {
		return false;
	}
	if (lni->stype != sqe->stype) {
		return false;
	}
	end = off_end(sqe->off, sqe->len);
	if (paddr->pos != end) {
		return false;
	}
	len = sqe->len + paddr->len;
	if (len > (size_t)len_max) {
		return false;
	}
	nxt = off_next(sqe->off, len_max);
	end = off_end(sqe->off, len);
	if (end > nxt) {
		return false;
	}
	if (!blobid_isequal(&paddr->bka.blobid, &sqe->blobid)) {
		return false;
	}
	return true;
}

bool silofs_sqe_append_ref(struct silofs_submitq_ent *sqe,
                           const struct silofs_paddr *paddr,
                           struct silofs_lnode_info *lni)
{
	silofs_assert_eq(paddr->len, lni->view_len);

	if (!sqe_isappendable(sqe, paddr, lni)) {
		return false;
	}
	if (sqe->cnt == 0) {
		blobid_assign(&sqe->blobid, &paddr->bka.blobid);
		sqe->off = paddr->pos;
		sqe->stype = lni->stype;
	}
	sqe->lbki[sqe->cnt++] = lni->lbki;
	sqe->len += (uint32_t)(paddr->len);
	return true;
}

static int sqe_setup_encrypted_iovs(struct silofs_submitq_ent *sqe,
                                    const struct silofs_submit_ref *refs_arr)
{
	const struct silofs_submit_ref *ref = NULL;
	const struct silofs_plink *plink = NULL;
	void *enc;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &refs_arr[i];
		plink = &ref->plink;
		err = sqe_setup_iov_at(sqe, i, plink->paddr.len);
		if (err) {
			return err;
		}
		enc = sqe->iov[i].iov_base;
		err = silofs_encrypt_view(sqe->uber, &plink->paddr,
		                          &plink->riv, ref->view, enc);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_sqe_assign_iovs(struct silofs_submitq_ent *sqe,
                           const struct silofs_submit_ref *refs_arr)
{
	int err;

	err = sqe_setup_encrypted_iovs(sqe, refs_arr);
	if (err) {
		sqe_reset_iovs(sqe);
	}
	return err;
}

void silofs_sqe_bind_blobf(struct silofs_submitq_ent *sqe,
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

static void sqe_unbind_blobf(struct silofs_submitq_ent *sqe)
{
	silofs_sqe_bind_blobf(sqe, NULL);
}

static int sqe_pwrite_iovs(const struct silofs_submitq_ent *sqe)
{
	return silofs_blobf_pwritevn(sqe->blobf, sqe->off,
	                             sqe->iov, sqe->cnt, true);
}

void silofs_sqe_increfs(struct silofs_submitq_ent *sqe)
{
	if (!sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lbki_incref(sqe->lbki[i]);
		}
		sqe->hold_refs = 1;
	}
}

static void sqe_decrefs(struct silofs_submitq_ent *sqe)
{
	if (sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lbki_decref(sqe->lbki[i]);
		}
		sqe->hold_refs = 0;
	}
}

static void sqe_init(struct silofs_submitq_ent *sqe,
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
	sqe->hold_refs = 0;
	sqe->status = 0;
}

static void sqe_fini(struct silofs_submitq_ent *sqe)
{
	list_head_fini(&sqe->qlh);
	sqe_reset_iovs(sqe);
	sqe_unbind_blobf(sqe);
	sqe->off = -1;
	sqe->len = 0;
	sqe->cnt = 0;
	sqe->alloc = NULL;
	sqe->status = -1;
}

static struct silofs_submitq_ent *
sqe_new(struct silofs_alloc *alloc, uint64_t uniq_id)
{
	struct silofs_submitq_ent *sqe;

	STATICASSERT_LE(sizeof(*sqe), 1024);

	sqe = silofs_allocate(alloc, sizeof(*sqe), 0);
	if (likely(sqe != NULL)) {
		sqe_init(sqe, alloc, uniq_id);
	}
	return sqe;
}

static void sqe_del(struct silofs_submitq_ent *sqe,
                    struct silofs_alloc *alloc)
{
	sqe_fini(sqe);
	silofs_deallocate(alloc, sqe, sizeof(*sqe), 0);
}

struct silofs_submitq_ent *silofs_sqe_from_qlh(struct silofs_list_head *qlh)
{
	struct silofs_submitq_ent *sqe = NULL;

	if (qlh != NULL) {
		sqe = container_of(qlh, struct silofs_submitq_ent, qlh);
	}
	return sqe;
}

static int sqe_apply(struct silofs_submitq_ent *sqe)
{
	sqe->status = sqe_pwrite_iovs(sqe);
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

static struct silofs_submitq_ent *
submitq_front_sqe(struct silofs_submitq *smq)
{
	struct silofs_list_head *lh;

	lh = listq_front(&smq->smq_listq);
	return silofs_sqe_from_qlh(lh);
}

static void submitq_unlink_sqe(struct silofs_submitq *smq,
                               struct silofs_submitq_ent *sqe)
{
	listq_remove(&smq->smq_listq, &sqe->qlh);
}

static void submitq_push_sqe(struct silofs_submitq *smq,
                             struct silofs_submitq_ent *sqe)
{
	listq_push_back(&smq->smq_listq, &sqe->qlh);
}

void silofs_submitq_enqueue(struct silofs_submitq *smq,
                            struct silofs_submitq_ent *sqe)
{
	silofs_mutex_lock(&smq->smq_mutex);
	submitq_push_sqe(smq, sqe);
	silofs_mutex_unlock(&smq->smq_mutex);
}

static struct silofs_submitq_ent *
submitq_get_sqe(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_ent *sqe;

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
                             struct silofs_submitq_ent **out_sqe)
{
	struct silofs_submitq_ent *sqe;
	int ret = 0;

	silofs_mutex_lock(&smq->smq_mutex);
	sqe = submitq_get_sqe(smq, id);
	if (sqe != NULL) {
		submitq_unlink_sqe(smq, sqe);
		ret = sqe_apply(sqe);
	}
	silofs_mutex_unlock(&smq->smq_mutex);
	*out_sqe = sqe;
	return ret;
}

static int submitq_apply(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_ent *sqe = NULL;
	int ret = 0;

	while (ret == 0) {
		sqe = NULL;
		ret = submitq_apply_one(smq, id, &sqe);
		if (sqe == NULL) {
			break;
		}
		silofs_submitq_del_sqe(smq, sqe);
	}
	return ret;
}

int silofs_submitq_new_sqe(struct silofs_submitq *smq,
                           struct silofs_submitq_ent **out_sqe)
{
	*out_sqe = sqe_new(smq->smq_alloc, smq->smq_apex_id++);
	return likely(*out_sqe != NULL) ? 0 : -SILOFS_ENOMEM;
}

void silofs_submitq_del_sqe(struct silofs_submitq *smq,
                            struct silofs_submitq_ent *sqe)
{
	sqe_decrefs(sqe);
	sqe_reset_iovs(sqe);
	sqe_unbind_blobf(sqe);
	sqe_del(sqe, smq->smq_alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cred_init(struct silofs_cred *cred)
{
	cred->uid = (uid_t)(-1);
	cred->gid = (gid_t)(-1);
	cred->umask = (mode_t)(-1);
}

static void cred_setup(struct silofs_cred *cred,
                       uid_t uid, gid_t gid, mode_t umsk)
{
	cred->uid = uid;
	cred->gid = gid;
	cred->umask = umsk;
}

static void cred_update_umask(struct silofs_cred *cred, mode_t umsk)
{
	cred->umask = umsk;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_set_creds(struct silofs_task *task,
                           uid_t uid, gid_t gid, mode_t umsk)
{
	cred_setup(&task->t_oper.op_creds.host_cred, uid, gid, umsk);
	cred_setup(&task->t_oper.op_creds.fs_cred, uid, gid, umsk);
}

void silofs_task_update_umask(struct silofs_task *task, mode_t umask)
{
	cred_update_umask(&task->t_oper.op_creds.host_cred, umask);
	cred_update_umask(&task->t_oper.op_creds.fs_cred, umask);
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
                           struct silofs_submitq_ent *sqe)
{
	if (sqe->uniq_id > task->t_apex_id) {
		task->t_apex_id = sqe->uniq_id;
	}
}

int silofs_task_submit(const struct silofs_task *task, bool all)
{
	int ret = 0;

	if (all) {
		ret = submitq_apply(task->t_submitq, SILOFS_CID_ALL);
	} else if (task->t_apex_id) {
		ret = submitq_apply(task->t_submitq, task->t_apex_id);
	}
	return ret;
}

struct silofs_sb_info *silofs_task_sbi(const struct silofs_task *task)
{
	return task->t_uber->ub_sbi;
}

struct silofs_cache *silofs_task_cache(const struct silofs_task *task)
{
	return task->t_uber->ub.cache;
}

const struct silofs_idsmap *silofs_task_idsmap(const struct silofs_task *task)
{
	return task->t_uber->ub.idsmap;
}

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}


int silofs_task_init(struct silofs_task *task, struct silofs_uber *uber)
{
	memset(task, 0, sizeof(*task));
	cred_init(&task->t_oper.op_creds.fs_cred);
	cred_init(&task->t_oper.op_creds.host_cred);
	task->t_uber = uber;
	task->t_submitq = uber->ub.submitq;
	task->t_apex_id = 0;
	task->t_interrupt = 0;
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
