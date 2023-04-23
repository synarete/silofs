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

/* TODO: cleanups and resource reclaim upon failure in every path */
static int stage_raw_vnode(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vi)
{
	const enum silofs_stg_mode stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;

	return silofs_stage_vnode(task, NULL, vaddr, stg_mode, out_vi);
}

static int do_spawn_vnode(struct silofs_task *task,
                          struct silofs_inode_info *pii,
                          enum silofs_stype stype,
                          struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa = { .oaddr.pos = -1 };
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_claim_vspace(task, stype, &voa);
	if (err) {
		return err;
	}
	err = stage_raw_vnode(task, &voa.vaddr, &vi);
	if (err) {
		return err;
	}
	silofs_stamp_meta_of(vi);
	vi_dirtify(vi, pii);
	*out_vi = vi;
	return 0;
}

int silofs_spawn_vnode_of(struct silofs_task *task,
                          struct silofs_inode_info *pii,
                          enum silofs_stype stype,
                          struct silofs_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = do_spawn_vnode(task, pii, stype, out_vi);
	ii_decref(pii);
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
	return (((mode & S_IFMT) | sup) == sup) ? 0 : -SILOFS_EOPNOTSUPP;
}

static int claim_inode(struct silofs_task *task,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_ivoaddr ivoa;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_claim_ispace(task, &ivoa);
	if (err) {
		return err;
	}
	err = stage_raw_vnode(task, &ivoa.voa.vaddr, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(ii, ivoa.ino);
	*out_ii = ii;
	return 0;
}

static void setup_new_inode(struct silofs_task *task,
                            struct silofs_inode_info *ii,
                            ino_t parent_ino, mode_t parent_mode,
                            mode_t mode, dev_t rdev)
{
	const uint64_t gen = make_next_generation(task);

	silofs_ii_stamp_mark_visible(ii);
	silofs_ii_setup_by(ii, task_creds(task), parent_ino,
	                   parent_mode, mode, rdev, gen);
}

int silofs_spawn_inode_of(struct silofs_task *task, ino_t parent_ino,
                          mode_t parent_mode, mode_t mode, dev_t rdev,
                          struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_itype(task, mode);
	if (err) {
		return err;
	}
	err = claim_inode(task, &ii);
	if (err) {
		return err;
	}
	setup_new_inode(task, ii, parent_ino, parent_mode, mode, rdev);
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

	err = silofs_resolve_voaddr_of(task, vaddr, SILOFS_STG_COW, &voa);
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

int silofs_remove_vnode_by(struct silofs_task *task,
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

int silofs_remove_vnode_of(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_stage_cached_vnode(task, vaddr, &vi);
	if (!err) {
		err = silofs_remove_vnode_by(task, vi);
	} else {
		err = reclaim_vspace_at(task, vaddr);
	}
	return err;
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

static void forget_cached_ii(const struct silofs_task *task,
                             struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);

	silofs_ii_undirtify(ii);
	forget_cached_vi(task, &ii->i_vi);
}

int silofs_remove_inode_by(struct silofs_task *task,
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
