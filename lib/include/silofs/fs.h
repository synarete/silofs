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
#ifndef SILOFS_FS_H_
#define SILOFS_FS_H_

#include <silofs/types.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/vfs.h>

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_CUR = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW = SILOFS_BIT(2), /* not-set-yet */
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* idsmap */

/* bi-directional id-mapping hash-table (external-internal) */
struct silofs_idsmap {
	struct silofs_alloc     *idm_alloc;
	struct silofs_list_head *idm_uhtof;
	struct silofs_list_head *idm_uftoh;
	struct silofs_list_head *idm_ghtof;
	struct silofs_list_head *idm_gftoh;
	size_t                   idm_uhcap;
	size_t                   idm_usize;
	size_t                   idm_ghcap;
	size_t                   idm_gsize;
	bool                     idm_allow_hostids;
};

int silofs_idsmap_init(struct silofs_idsmap *idsm, struct silofs_alloc *alloc);

void silofs_idsmap_fini(struct silofs_idsmap *idsm);

void silofs_idsmap_clear(struct silofs_idsmap *idsm);

int silofs_idsmap_populate(struct silofs_idsmap      *idsm,
                           const struct silofs_fsids *fsids,
                           bool                       allow_hostids);

int silofs_idsmap_mapcreds(const struct silofs_idsmap *idsm, uid_t host_uid,
                           gid_t host_gid, uid_t *out_fs_uid,
                           gid_t *out_fs_gid);

int silofs_idsmap_rmapcreds(const struct silofs_idsmap *idsm, uid_t fs_uid,
                            gid_t fs_gid, uid_t *out_fs_uid,
                            gid_t *out_fs_gid);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pvglue */

int silofs_stage_xanode(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr    *vaddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_xanode_info   **out_xai);

int silofs_spawn_xanode(struct silofs_task_ctx     *task,
                        struct silofs_inode_info   *pii,
                        struct silofs_xanode_info **out_xai);

int silofs_remove_xanode_at(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>

#include <silofs/fs/lsmap.h>
#include <silofs/fs/task.h>
#include <silofs/fs/super.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/vstage.h>
#include <silofs/fs/encdec.h>
#include <silofs/fs/flush.h>

#endif /* SILOFS_FS_H_ */
