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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>

#define SILOFS_COMMIT_LEN_MAX   SILOFS_MEGA
#define SILOFS_CID_ALL          UINT64_MAX

static int sqe_setup_iov_at(struct silofs_submitq_ent *sqe,
                            size_t idx, size_t len)
{
	STATICASSERT_LE(ARRAY_SIZE(sqe->iov), SILOFS_IOV_MAX);

	silofs_assert_lt(idx, ARRAY_SIZE(sqe->iov));
	silofs_assert_null(sqe->iov[idx].iov_base);

	sqe->iov[idx].iov_base = silofs_memalloc(sqe->alloc, len, 0);
	if (sqe->iov[idx].iov_base == NULL) {
		return -SILOFS_ENOMEM;
	}
	sqe->iov[idx].iov_len = len;
	return 0;
}

static void sqe_reset_iovs(struct silofs_submitq_ent *sqe)
{
	for (size_t idx = 0; idx < sqe->cnt; ++idx) {
		silofs_memfree(sqe->alloc, sqe->iov[idx].iov_base,
		               sqe->iov[idx].iov_len, SILOFS_ALLOCF_NOPUNCH);
		sqe->iov[idx].iov_base = NULL;
		sqe->iov[idx].iov_len = 0;
	}
}

static bool sqe_isappendable(const struct silofs_submitq_ent *sqe,
                             const struct silofs_laddr *laddr)
{
	const struct silofs_laddr *sqe_laddr = &sqe->laddr;
	const ssize_t len_max = SILOFS_COMMIT_LEN_MAX;
	size_t len;
	loff_t end;
	loff_t nxt;

	STATICASSERT_EQ(ARRAY_SIZE(sqe->iov), ARRAY_SIZE(sqe->lni));

	if (sqe->cnt == 0) {
		return true;
	}
	if (sqe->cnt == ARRAY_SIZE(sqe->iov)) {
		return false;
	}
	if (!silofs_laddr_isnext(sqe_laddr, laddr)) {
		return false;
	}
	len = sqe_laddr->len + laddr->len;
	if (len > (size_t)len_max) {
		return false;
	}
	/* for inodes require alignment on commit-len boundaries */
	if (ltype_isinode(sqe->ltype)) {
		nxt = off_next(sqe_laddr->pos, len_max);
		end = off_end(sqe_laddr->pos, len);
		if (end > nxt) {
			return false;
		}
	}
	return true;
}

bool silofs_sqe_append_ref(struct silofs_submitq_ent *sqe,
                           const struct silofs_laddr *laddr,
                           struct silofs_lnode_info *lni)
{
	if (!sqe_isappendable(sqe, laddr)) {
		return false;
	}
	if (sqe->cnt == 0) {
		laddr_assign(&sqe->laddr, laddr);
		sqe->ltype = lni->ln_ltype;
	} else {
		sqe->laddr.len += laddr->len;
	}
	sqe->lni[sqe->cnt++] = lni;
	return true;
}

static int sqe_setup_iovs(struct silofs_submitq_ent *sqe,
                          const struct silofs_submit_ref *refs_arr)
{
	const struct silofs_submit_ref *ref;
	size_t len;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &refs_arr[i];
		len = ref->llink.laddr.len;
		err = sqe_setup_iov_at(sqe, i, len);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int sqe_encrypted_iovs(struct silofs_submitq_ent *sqe,
                              const struct silofs_submit_ref *refs_arr)
{
	const struct silofs_submit_ref *ref = NULL;
	const struct silofs_llink *llink = NULL;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &refs_arr[i];
		llink = &ref->llink;
		err = silofs_encrypt_view(sqe->fsenv, &llink->laddr,
		                          &llink->riv, ref->view,
		                          sqe->iov[i].iov_base);
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

	err = sqe_setup_iovs(sqe, refs_arr);
	if (err) {
		goto out_err;
	}
	err = sqe_encrypted_iovs(sqe, refs_arr);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	sqe_reset_iovs(sqe);
	return err;
}

static int sqe_do_write(const struct silofs_submitq_ent *sqe)
{
	return silofs_repo_writev_at(sqe->fsenv->fse.repo,
	                             &sqe->laddr, sqe->iov, sqe->cnt);
}

void silofs_sqe_increfs(struct silofs_submitq_ent *sqe)
{
	if (!sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lni_incref(sqe->lni[i]);
		}
		sqe->hold_refs = 1;
	}
}

static void sqe_decrefs(struct silofs_submitq_ent *sqe)
{
	if (sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lni_decref(sqe->lni[i]);
		}
		sqe->hold_refs = 0;
	}
}

static void sqe_init(struct silofs_submitq_ent *sqe,
                     struct silofs_alloc *alloc, uint64_t uniq_id)
{
	memset(sqe, 0, sizeof(*sqe));
	list_head_init(&sqe->qlh);
	laddr_reset(&sqe->laddr);
	sqe->alloc = alloc;
	sqe->fsenv = NULL;
	sqe->uniq_id = uniq_id;
	sqe->cnt = 0;
	sqe->hold_refs = 0;
	sqe->status = 0;
}

static void sqe_fini(struct silofs_submitq_ent *sqe)
{
	list_head_fini(&sqe->qlh);
	laddr_reset(&sqe->laddr);
	sqe_reset_iovs(sqe);
	sqe->cnt = 0;
	sqe->alloc = NULL;
	sqe->status = -1;
}

static struct silofs_submitq_ent *
sqe_new(struct silofs_alloc *alloc, uint64_t uniq_id)
{
	struct silofs_submitq_ent *sqe;

	STATICASSERT_LE(sizeof(*sqe), 1024);

	sqe = silofs_memalloc(alloc, sizeof(*sqe), 0);
	if (likely(sqe != NULL)) {
		sqe_init(sqe, alloc, uniq_id);
	}
	return sqe;
}

static void sqe_del(struct silofs_submitq_ent *sqe,
                    struct silofs_alloc *alloc)
{
	sqe_fini(sqe);
	silofs_memfree(alloc, sqe, sizeof(*sqe), SILOFS_ALLOCF_NOPUNCH);
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
	sqe->status = sqe_do_write(sqe);
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

static int task_apply(const struct silofs_task *task, bool all)
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
	return task->t_fsenv->fse_sbi;
}

struct silofs_lcache *silofs_task_lcache(const struct silofs_task *task)
{
	return task->t_fsenv->fse.lcache;
}

struct silofs_repo *silofs_task_repo(const struct silofs_task *task)
{
	return task->t_fsenv->fse.repo;
}

const struct silofs_idsmap *silofs_task_idsmap(const struct silofs_task *task)
{
	return task->t_fsenv->fse.idsmap;
}

const struct silofs_creds *silofs_task_creds(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}


void silofs_task_init(struct silofs_task *task, struct silofs_fsenv *fsenv)
{
	memset(task, 0, sizeof(*task));
	cred_init(&task->t_oper.op_creds.fs_cred);
	cred_init(&task->t_oper.op_creds.host_cred);
	task->t_fsenv = fsenv;
	task->t_submitq = fsenv->fse.submitq;
	task->t_looseq = NULL;
	task->t_apex_id = 0;
	task->t_interrupt = 0;
	task->t_fs_locked = false;
	task->t_ex_locked = false;
	task->t_exclusive = false;
	task->t_uber_op = false;
	task->t_kwrite = false;
}

void silofs_task_fini(struct silofs_task *task)
{
	silofs_assert_null(task->t_looseq);
	silofs_assert_eq(task->t_fs_locked, false);

	task->t_fsenv = NULL;
	task->t_submitq = NULL;
}

void silofs_task_enq_loose(struct silofs_task *task,
                           struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_vni.vn_lni.ln_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		ii->i_looseq_next = task->t_looseq;
		ii->i_in_looseq = true;
		task->t_looseq = ii;
		ii_incref(ii);
	}
}

static struct silofs_inode_info *
task_deq_loose(struct silofs_task *task)
{
	struct silofs_inode_info *ii = NULL;

	if (task->t_looseq != NULL) {
		ii = task->t_looseq;
		task->t_looseq = ii->i_looseq_next;
		ii->i_looseq_next = NULL;
		ii->i_in_looseq = false;
		ii_decref(ii);
	}
	return ii;
}

static void task_forget_looseq(struct silofs_task *task)
{
	struct silofs_inode_info *ii;
	int err;

	ii = task_deq_loose(task);
	while (ii != NULL) {
		err = silofs_forget_loose_ii(task, ii);
		if (err) {
			/* TODO: maybe have retry loop ? */
			silofs_panic("failed to forget loose inode: "
			             "ino=%ld flags=%x err=%d", ii->i_ino,
			             ii->i_vni.vn_lni.ln_flags, err);
		}
		ii = task_deq_loose(task);
	}
}

static void task_purge(struct silofs_task *task)
{
	if (task->t_looseq != NULL) {
		if (task->t_fs_locked) {
			/* case 1: already fs-locked; keep it locked post op */
			task_forget_looseq(task);
		} else {
			/* case 2: need to protect with fs-lock/unlock pair */
			silofs_task_lock_fs(task);
			task_forget_looseq(task);
			silofs_task_unlock_fs(task);
		}
	}
}

void silofs_task_lock_fs(struct silofs_task *task)
{
	if (!task->t_fs_locked && !task->t_uber_op) {
		silofs_fsenv_lock(task->t_fsenv);
		task->t_fs_locked = true;
	}
}

void silofs_task_unlock_fs(struct silofs_task *task)
{
	if (task->t_fs_locked && !task->t_uber_op) {
		silofs_fsenv_unlock(task->t_fsenv);
		task->t_fs_locked = false;
	}
}

void silofs_task_rwlock_fs(struct silofs_task *task)
{
	if (!task->t_ex_locked) {
		silofs_fsenv_rwlock(task->t_fsenv, task->t_exclusive);
		task->t_ex_locked = true;
	}
}

void silofs_task_rwunlock_fs(struct silofs_task *task)
{
	if (task->t_ex_locked) {
		silofs_fsenv_rwunlock(task->t_fsenv);
		task->t_ex_locked = false;
	}
}

static bool task_has_looseq(const struct silofs_task *task)
{
	return (task->t_looseq != NULL);
}

int silofs_task_submit(struct silofs_task *task, bool all)
{
	int ret;

	ret = task_apply(task, all || task_has_looseq(task));
	task_purge(task);
	return ret;
}
