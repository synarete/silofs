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
#ifndef SILOFS_FILEP_H_
#define SILOFS_FILEP_H_

#ifndef SILOFS_USE_FILE_PRIVATE
#error "file private header -- do not include"
#endif

enum silofs_file_op {
	SILOFS_FILE_OP_NONE       = 0,
	SILOFS_FILE_OP_READ       = 1,
	SILOFS_FILE_OP_WRITE      = 2,
	SILOFS_FILE_OP_TRUNC      = 3,
	SILOFS_FILE_OP_FALLOC     = 4,
	SILOFS_FILE_OP_FIEMAP     = 5,
	SILOFS_FILE_OP_LSEEK      = 6,
	SILOFS_FILE_OP_COPY_RANGE = 7,
	SILOFS_FILE_OP_DROP       = 8,
};

enum silofs_file_leaf_size {
	SILOFS_FILE_HEAD1_LEAF_SIZE = SILOFS_FILE_DATA_NODE1_SIZE,
	SILOFS_FILE_HEAD2_LEAF_SIZE = SILOFS_FILE_DATA_NODE4_SIZE,
	SILOFS_FILE_TREE_LEAF_SIZE  = SILOFS_FILE_DATA_NODE64_SIZE,
};

struct silofs_file_ctx {
	enum silofs_file_op           op;
	enum silofs_stg_mode          stg_mode;
	const struct silofs_task_ctx *task;
	struct silofs_inode_info     *ii;
	struct silofs_rwiter_ctx     *rwi_ctx;
	struct fiemap                *fm;
	size_t                        len;
	off_t                         beg;
	off_t                         off;
	off_t                         end;
	int                           fl_mode;
	int                           fm_flags;
	int                           fm_stop;
	int                           cp_flags;
	int                           whence;
	int                           with_backref;
	int                           o_flags;
	bool                          kill_suidgid;
};

struct silofs_flnode_ref {
	struct silofs_laddr        laddr;
	struct silofs_inode_info  *ii;
	struct silofs_ftnode_info *parent_fti;
	off_t                      file_pos;
	size_t                     slot_idx;
	size_t                     leaf_size;
	bool                       head1;
	bool                       head2;
	bool                       tree;
	bool                       partial;
	bool                       shared;
	bool                       has_data;
	bool                       has_hole;
	bool                       unwritten;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline off_t off_diff(off_t off1, off_t off2)
{
	return silofs_off_diff(off1, off2);
}

static inline off_t off_max(off_t off1, off_t off2)
{
	return silofs_off_max(off1, off2);
}

static inline off_t off_max3(off_t off1, off_t off2, off_t off3)
{
	return silofs_off_max3(off1, off2, off3);
}

static inline off_t off_clamp(off_t off, off_t off_lo, off_t off_hi)
{
	return silofs_off_clamp(off, off_lo, off_hi);
}

static inline bool off_within(off_t off, off_t beg, off_t end)
{
	return silofs_off_within(off, beg, end);
}

static inline size_t off_ulen(off_t beg, off_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

static inline bool off_lbk_aligned(off_t off)
{
	return (off % SILOFS_LBK_SIZE) == 0;
}

static inline off_t off_align_to_lbk(off_t off)
{
	return silofs_off_align(off, SILOFS_LBK_SIZE);
}

static inline off_t off_next(off_t off, ssize_t len)
{
	return silofs_off_next(off, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_laddr_isnull(laddr);
}

static inline size_t laddr_len(const struct silofs_laddr *laddr)
{
	return silofs_laddr_len(laddr);
}

static inline const struct silofs_laddr *laddr_none(void)
{
	return silofs_laddr_none();
}

#endif /* SILOFS_FILEP_H_ */
