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
#include <silofs/pv.h>
#include <silofs/fs.h>

static bool isock_allowed(const struct silofs_task_ctx *task)
{
	return (task->ubref->ctl_flags & SILOFS_F_ALLOW_ISOCK) > 0;
}

static bool ififo_allowed(const struct silofs_task_ctx *task)
{
	return (task->ubref->ctl_flags & SILOFS_F_ALLOW_IFIFO) > 0;
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

static int get_sbi(const struct silofs_task_ctx *task,
                   struct silofs_sbnode_info2 **out_sbi)
{
	int err;

	err = silofs_curr_sbi2(task, out_sbi);
	return_if_err(err);

	silofs_sbi2_incref(*out_sbi);
	return 0;
}

static void put_sbi(struct silofs_sbnode_info2 *sbi)
{
	if (sbi != nullptr) {
		silofs_sbi2_decref(sbi);
	}
}

int silofs_spawn_inode_by(struct silofs_task_ctx *task,
                          const struct silofs_inew_params *inp,
                          struct silofs_inode_info **out_ii)
{
	struct silofs_sbnode_info2 *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	err = check_itype(task, inp->mode);
	return_if_err(err);

	err = silofs_spawn_inode2(task, out_ii);
	goto_out_if_err(err);

	silofs_ii_update_spawned(*out_ii, inp);
	silofs_sbi2_take_inode(sbi);
out:
	put_sbi(sbi);
	return err;
}

static void
vaddr_of(const struct silofs_inode_info *ii, struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr_assign(out_vaddr, silofs_ii_vaddr(ii));
}

int silofs_remove_inode_by(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii)
{
	struct silofs_vaddr vaddr;
	struct silofs_sbnode_info2 *sbi = nullptr;
	int err;

	err = get_sbi(task, &sbi);
	goto_out_if_err(err);

	vaddr_of(ii, &vaddr);
	silofs_ii_cleardirty(ii);

	err = silofs_remove_inode2(task, &vaddr);
	goto_out_if_err(err);

	silofs_sbi2_give_inode(sbi);
out:
	put_sbi(sbi);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int resolve_inode_vaddr(ino_t ino, struct silofs_vaddr *out_vaddr)
{
	silofs_ino_to_vaddr(ino, out_vaddr);
	return !silofs_vaddr_isnull(out_vaddr) ? 0 : -SILOFS_EINVAL;
}

static int stage_update_inode_at(struct silofs_task_ctx *task,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_inode_info **out_ii)
{
	int err;

	err = silofs_stage_inode2(task, vaddr, stg_mode, out_ii);
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
	struct silofs_vaddr vaddr;
	int err;

	err = resolve_inode_vaddr(ino, &vaddr);
	return_if_err(err);

	err = silofs_probe_inode2(task, &vaddr);
	return_if_err(err);

	err = stage_update_inode_at(task, &vaddr, stg_mode, out_ii);
	return_if_err(err);

	err = ii_check_post_stage(*out_ii, stg_mode);
	return_if_err(err);

	return 0;
}

static int fetch_cached_vni(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_vnode_info **out_vni)
{
	*out_vni = silofs_vcache_lookup_vnode(task->vcache, vaddr);
	return (*out_vni == nullptr) ? -SILOFS_ENOENT : 0;
}

static int
fetch_cached_ii(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
                struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = fetch_cached_vni(task, vaddr, &vni);
	return_if_err(err);

	*out_ii = silofs_ii_from_vni(vni);
	return 0;
}

int silofs_lookup_cached_inode(struct silofs_task_ctx *task, ino_t ino,
                               struct silofs_inode_info **out_ii)
{
	struct silofs_vaddr vaddr = { .off = -1 };
	int err;

	err = resolve_inode_vaddr(ino, &vaddr);
	return_if_err(err);

	err = fetch_cached_ii(task, &vaddr, out_ii);
	return_if_err(err);

	return 0;
}
