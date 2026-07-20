/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/addr.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

static bool isock_allowed(const struct silofs_task_ctx *task)
{
	return (task->corefs->fsroot->ctl_flags & SILOFS_F_ALLOW_ISOCK) > 0;
}

static bool ififo_allowed(const struct silofs_task_ctx *task)
{
	return (task->corefs->fsroot->ctl_flags & SILOFS_F_ALLOW_IFIFO) > 0;
}

static int check_itype(const struct silofs_task_ctx *task, mode_t mode)
{
	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 *
	 * Have explicit control in 'allow_ispecial' from mount command and
	 * by mount flags.
	 */
	const mode_t itype = mode & S_IFMT;
	int ret;

	switch (itype) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
		ret = 0;
		break;
	case S_IFSOCK:
		ret = isock_allowed(task) ? 0 : -SILOFS_EOPNOTSUPP;
		break;
	case S_IFIFO:
		ret = ififo_allowed(task) ? 0 : -SILOFS_EOPNOTSUPP;
		break;
	case S_IFCHR:
	case S_IFBLK:
	default:
		ret = -SILOFS_EOPNOTSUPP;
		break;
	}
	return ret;
}

int silofs_spawn_inode_by(struct silofs_task_ctx *task,
                          const struct silofs_inew_params *inp,
                          struct silofs_inode_info **out_ii)
{
	int err;

	err = check_itype(task, inp->mode);
	return_if_err(err);

	err = silofs_spawn_inode2(task, out_ii);
	return_if_err(err);

	silofs_ii_update_spawned(*out_ii, inp);
	return 0;
}

static void
laddr_of(const struct silofs_inode_info *ii, struct silofs_laddr *out_laddr)
{
	silofs_laddr_assign(out_laddr, silofs_ii_laddr(ii));
}

int silofs_remove_inode_by(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii)
{
	struct silofs_laddr laddr;

	laddr_of(ii, &laddr);
	silofs_ii_cleardirty(ii);

	return silofs_remove_inode2(task, &laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int resolve_inode_laddr(ino_t ino, struct silofs_laddr *out_laddr)
{
	silofs_ino_to_laddr(ino, out_laddr);
	return !silofs_laddr_isnull(out_laddr) ? 0 : -SILOFS_EINVAL;
}

static int stage_update_inode_at(struct silofs_task_ctx *task,
                                 const struct silofs_laddr *laddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_inode_info **out_ii)
{
	int err;

	err = silofs_stage_inode2(task, laddr, stg_mode, out_ii);
	return_if_err(err);

	silofs_ii_update_staged(*out_ii);
	return 0;
}

/*
 * TODO-0027: Support immutable inodes via explicit ioctl
 *
 * Special inode state, correlates to STATX_ATTR_IMMUTABLE
 */
static bool ii_isimmutable(const struct silofs_inode_info *ii)
{
	silofs_unused(ii);
	return false;
}

static int ii_check_post_stage(const struct silofs_inode_info *ii,
                               enum silofs_stg_mode stg_mode)
{
	if ((stg_mode & SILOFS_STG_COW) == 0) {
		return 0;
	}
	if (ii_isimmutable(ii)) {
		return -SILOFS_EACCES;
	}
	return 0;
}

int silofs_stage_inode_by(struct silofs_task_ctx *task, ino_t ino,
                          enum silofs_stg_mode stg_mode,
                          struct silofs_inode_info **out_ii)
{
	struct silofs_laddr laddr;
	int err;

	err = resolve_inode_laddr(ino, &laddr);
	return_if_err(err);

	err = silofs_probe_inode2(task, &laddr);
	return_if_err(err);

	err = stage_update_inode_at(task, &laddr, stg_mode, out_ii);
	return_if_err(err);

	err = ii_check_post_stage(*out_ii, stg_mode);
	return_if_err(err);

	return 0;
}

static int fetch_cached_lni(const struct silofs_task_ctx *task,
                            const struct silofs_laddr *laddr,
                            struct silofs_lnode_info **out_lni)
{
	*out_lni = silofs_lcache_lookup_lnode(task->corefs->lcache, laddr);
	return (*out_lni == nullptr) ? -SILOFS_ENOENT : 0;
}

static int fetch_cached_ii(const struct silofs_task_ctx *task,
                           const struct silofs_laddr *laddr,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = fetch_cached_lni(task, laddr, &lni);
	return_if_err(err);

	*out_ii = silofs_ii_from_lni(lni);
	return 0;
}

int silofs_lookup_cached_inode(const struct silofs_task_ctx *task, ino_t ino,
                               struct silofs_inode_info **out_ii)
{
	struct silofs_laddr laddr = { .off = -1 };
	int err;

	err = resolve_inode_laddr(ino, &laddr);
	return_if_err(err);

	err = fetch_cached_ii(task, &laddr, out_ii);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & SILOFS_CTLF_RELEASE) {
		threshold = SILOFS_MEGA / 2;
	} else if (flags & SILOFS_CTLF_INTERN) {
		threshold = SILOFS_MEGA;
	} else if (flags & SILOFS_CTLF_OPSTART) {
		threshold = 2 * SILOFS_MEGA;
	} else {
		threshold = 4 * SILOFS_MEGA;
	}
	return threshold;
}

static bool need_flush_by_alloc(const struct silofs_alloc *alloc)
{
	struct silofs_alloc_stat alst = {
		.nbytes_use = 0,
		.nbytes_max = 0,
	};

	silofs_memstat(alloc, &alst);
	return (alst.nbytes_use > (alst.nbytes_max / 2));
}

static bool need_flush_by_ii(const struct silofs_inode_info *ii, int flags)
{
	size_t threshold;

	if (flags & (SILOFS_CTLF_NOW | SILOFS_CTLF_FSYNC)) {
		return true;
	}
	threshold = flush_threshold_of(flags);
	silofs_unused(ii);        /* XXX TODO : use me */
	silofs_unused(threshold); /* XXX TODO : use me */
	return false;
}

static bool need_flush(const struct silofs_core_refs *corefs,
                       const struct silofs_inode_info *ii, int flags)
{
	return (need_flush_by_ii(ii, flags) ||
	        need_flush_by_alloc(corefs->alloc));
}

int silofs_flush_dirty_of(const struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii, int flags)
{
	if (unlikely(ii == nullptr)) {
		return 0;
	}
	if (!silofs_ii_isdirty(ii)) {
		return 0;
	}
	if (!need_flush(task->corefs, ii, flags)) {
		return 0;
	}
	return silofs_destage_dirty_nodes(task->corefs);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
enq_loose_inode(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	if (!ii->i_in_looseq) {
		ii->i_looseq_next = task->looseq;
		ii->i_in_looseq   = true;
		task->looseq      = ii;
		silofs_ii_incref(ii);
	}
}

static struct silofs_inode_info *deq_loose_inode(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;

	if (task->looseq != nullptr) {
		ii                = task->looseq;
		task->looseq      = ii->i_looseq_next;
		ii->i_looseq_next = nullptr;
		ii->i_in_looseq   = false;
		silofs_ii_decref(ii);
	}
	return ii;
}

void silofs_purge_loose_inodes(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii;
	int err;

	ii = deq_loose_inode(task);
	while (ii != nullptr) {
		err = silofs_forget_loose_ii(task, ii);
		if (err) {
			/* TODO: maybe have retry loop ? */
			silofs_panic("failed to forget loose inode: "
			             "ino=%ld flags=%x err=%d",
			             ii->i_ino, ii->i_lni.vn_flags, err);
		}
		ii = deq_loose_inode(task);
	}
}

void silofs_enqueue_loose_inode(struct silofs_task_ctx *task,
                                struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_lni.vn_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		enq_loose_inode(task, ii);
	}
}
