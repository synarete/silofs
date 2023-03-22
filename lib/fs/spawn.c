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

static int do_spawn_vnode(struct silofs_task *task,
                          struct silofs_inode_info *pii,
                          enum silofs_stype stype, silofs_dqid_t dqid,
                          struct silofs_vnode_info **out_vi)
{
	int err;

	err = silofs_claim_vnode(task, pii, stype, dqid, out_vi);
	if (err) {
		return err;
	}
	silofs_vi_stamp_mark_visible(*out_vi);
	silofs_vi_set_dqid(*out_vi, dqid);
	return 0;
}

int silofs_spawn_vnode(struct silofs_task *task,
                       struct silofs_inode_info *pii,
                       enum silofs_stype stype,
                       struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	const silofs_dqid_t dqid = pii ? ii_ino(pii) : SILOFS_DQID_DFL;
	int err;

	ii_incref(pii);
	err = do_spawn_vnode(task, pii, stype, dqid, &vi);
	if (!err) {
		silofs_assert_eq(vi->v_pii, pii);
	}
	ii_decref(pii);
	*out_vi = vi;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_creds *task_creds(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}

static uint64_t make_next_generation(struct silofs_task *task)
{
	struct silofs_sb_info *sbi = task_sbi(task);
	uint64_t gen = 0;

	silofs_sti_next_generation(&sbi->sb_sti, &gen);
	silofs_assert_gt(gen, 0);
	return gen;
}

static int check_itype(const struct silofs_task *task, mode_t mode)
{
	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 */
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
	                   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	silofs_unused(task);
	return (((mode & S_IFMT) | sup) == sup) ? 0 : -EOPNOTSUPP;
}

int silofs_spawn_inode(struct silofs_task *task, ino_t parent,
                       mode_t parent_mode, mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii)
{
	const struct silofs_creds *creds = task_creds(task);
	struct silofs_inode_info *ii = NULL;
	uint64_t gen;
	int err;

	err = check_itype(task, mode);
	if (err) {
		return err;
	}
	err = silofs_claim_inode(task, &ii);
	if (err) {
		return err;
	}
	gen = make_next_generation(task);
	silofs_ii_stamp_mark_visible(ii);
	silofs_ii_setup_by(ii, creds, parent, parent_mode, mode, rdev, gen);
	*out_ii = ii;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_cache *task_cache(const struct silofs_task *task)
{
	return task->t_uber->ub.cache;
}

static void forget_cached_vi(const struct silofs_task *task,
                             struct silofs_vnode_info *vi)
{
	silofs_cache_forget_vi(task_cache(task), vi);
}

static int reclaim_vspace_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_voaddr voa;
	int err;

	err = silofs_resolve_voaddr_of(task, vaddr, SILOFS_STAGE_COW, &voa);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(task, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int remove_vnode_of(struct silofs_task *task,
                           struct silofs_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = reclaim_vspace_at(task, vi_vaddr(vi));
	vi_decref(vi);
	return err;
}

int silofs_remove_vnode(struct silofs_task *task,
                        struct silofs_vnode_info *vi)
{
	int err;

	err = remove_vnode_of(task, vi);
	if (err) {
		return err;
	}
	forget_cached_vi(task, vi);
	return 0;
}

int silofs_remove_vnode_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_lookup_cached_vi(task, vaddr, &vi);
	if (!err) {
		err = silofs_remove_vnode(task, vi);
	} else {
		err = reclaim_vspace_at(task, vaddr);
	}
	return err;
}

static void forget_cached_ii(const struct silofs_task *task,
                             struct silofs_inode_info *ii)
{
	forget_cached_vi(task, &ii->i_vi);
}

static int reclaim_ispace_at(struct silofs_task *task,
                             const struct silofs_iaddr *iaddr)
{
	return reclaim_vspace_at(task, &iaddr->vaddr);
}

static void ii_iaddr(const struct silofs_inode_info *ii,
                     struct silofs_iaddr *out_iaddr)
{
	vaddr_assign(&out_iaddr->vaddr, ii_vaddr(ii));
	out_iaddr->ino = ii_ino(ii);
}

static int remove_inode_of(struct silofs_task *task,
                           struct silofs_inode_info *ii)
{
	struct silofs_iaddr iaddr = { .ino = SILOFS_INO_NULL };
	int err;

	ii_iaddr(ii, &iaddr);
	ii_incref(ii);
	err = reclaim_ispace_at(task, &iaddr);
	ii_decref(ii);
	return err;
}

int silofs_remove_inode(struct silofs_task *task,
                        struct silofs_inode_info *ii)
{
	int err;

	err = remove_inode_of(task, ii);
	if (err) {
		return err;
	}
	forget_cached_ii(task, ii);
	return 0;
}
