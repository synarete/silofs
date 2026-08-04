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
#ifndef SILOFS_DIRP_H_
#define SILOFS_DIRP_H_

#ifndef SILOFS_USE_DIR_PRIVATE
#error "dir private header -- do not include"
#endif

/* maximum depth of directory tree-mapping */
#define SILOFS_DTREE_DEPTH_MAX (4L)

/* non-valid dir's tree-mapping node-index (out-of-band sentinel) */
#define SILOFS_DTREE_INDEX_NULL (UINT32_MAX)

/* node-index of dir's tree-mapping root */
#define SILOFS_DTREE_INDEX_ROOT (0)

/* max dir-node index of tree-mapping nodes (0-based) */
#define SILOFS_DTREE_INDEX_MAX \
	(((1L << (SILOFS_DTREE_NODE_SHIFT * (SILOFS_DTREE_DEPTH_MAX + 1))) \
	  - 1L) / (SILOFS_DTREE_NODE_NCHILDS - 1) - 1)

/* max entries in directory */
#define SILOFS_DIR_ENTRIES_MAX \
	(SILOFS_DTREE_NODE_NENTS * SILOFS_DTREE_INDEX_MAX)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

typedef uint64_t silofs_dtn_index_t;
typedef uint64_t silofs_dtn_ord_t;
typedef uint32_t silofs_dtn_depth_t;

enum silofs_dtree_consts {
	DTREE_SHIFT      = SILOFS_DTREE_NODE_SHIFT,
	DTREE_FANOUT     = SILOFS_DTREE_NODE_NCHILDS,
	DTREE_DEPTH_MAX  = SILOFS_DTREE_DEPTH_MAX,
	DTREE_INDEX_NULL = SILOFS_DTREE_INDEX_NULL,
	DTREE_INDEX_ROOT = SILOFS_DTREE_INDEX_ROOT,
	DTREE_INDEX_MAX  = SILOFS_DTREE_INDEX_MAX,
	DTREE_OFF_SHIFT  = 13,
};

enum silofs_de_consts {
	DE_NAME_HASH_SHIFT = 24,
	DE_NAME_HASH_MASK  = (1U << DE_NAME_HASH_SHIFT) - 1
};

struct silofs_dir_entry_info {
	struct silofs_dtnode_info *dti;
	struct silofs_dir_entry   *de;
	struct silofs_ino_dt       ino_dt;
};

struct silofs_dir_ctx {
	const struct silofs_task_ctx *task;
	struct silofs_inode_info     *dir_ii;
	struct silofs_inode_info     *parent_ii;
	struct silofs_inode_info     *child_ii;
	struct silofs_readdir_ctx    *rd_ctx;
	const struct silofs_namestr  *name;
	enum silofs_stg_mode          stg_mode;
	int                           keep_iter;
	int                           readdir_plus;
};

#endif /* SILOFS_DIRP_H_ */
