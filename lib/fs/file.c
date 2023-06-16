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
#include <linux/falloc.h>
#include <linux/fiemap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#define STATICASSERT_NELEMS(x, y) \
	SILOFS_STATICASSERT_EQ(SILOFS_ARRAY_SIZE(x), y)

#define OP_READ         (1 << 0)
#define OP_WRITE        (1 << 1)
#define OP_TRUNC        (1 << 2)
#define OP_FALLOC       (1 << 3)
#define OP_FIEMAP       (1 << 4)
#define OP_LSEEK        (1 << 5)
#define OP_COPY_RANGE   (1 << 6)


struct silofs_file_ctx {
	struct silofs_task             *task;
	struct silofs_uber             *uber;
	struct silofs_sb_info          *sbi;
	struct silofs_inode_info       *ii;
	struct silofs_rwiter_ctx       *rwi_ctx;
	struct fiemap                  *fm;
	size_t  len;
	loff_t  beg;
	loff_t  off;
	loff_t  end;
	int     op_mask;
	int     fl_mode;
	int     fm_flags;
	int     fm_stop;
	int     cp_flags;
	int     whence;
	int     with_backref;
	enum silofs_stg_mode stg_mode;
};

struct silofs_fpos_ref {
	const struct silofs_file_ctx *f_ctx;
	struct silofs_finode_info *fni;
	struct silofs_vaddr vaddr;
	struct silofs_oaddr oaddr;
	loff_t  file_pos;
	size_t  slot_idx;
	bool    head1;
	bool    head2;
	bool    tree;
	bool    leaf;
	bool    partial;
	bool    shared;
	bool    has_data;
	bool    has_hole;
	bool    has_target;
	bool    unwritten;
};

/* local functions forward declarations */
static int fpr_unshare_leaf(struct silofs_fpos_ref *fpr);


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool off_is_bk_aligned(loff_t off)
{
	return (off % SILOFS_LBK_SIZE) == 0;
}

static loff_t off_in_data(loff_t off, enum silofs_stype stype)
{
	const ssize_t len = stype_ssize(stype);

	return off % len;
}

static size_t len_to_next(loff_t off, enum silofs_stype stype)
{
	const ssize_t len = stype_ssize(stype);
	const loff_t next = off_next(off, len);

	return off_ulen(off, next);
}

static size_t len_of_data(loff_t off, loff_t end, enum silofs_stype stype)
{
	const ssize_t len = stype_ssize(stype);
	const loff_t next = off_next(off, len);

	return (next < end) ? off_ulen(off, next) : off_ulen(off, end);
}

static bool off_is_partial(loff_t off, loff_t end, enum silofs_stype stype)
{
	const ssize_t len = stype_ssize(stype);
	const ssize_t io_len = off_len(off, end);
	const loff_t off_start = off_align(off, len);

	return (off != off_start) || (io_len < len);
}

static bool off_is_partial_head1(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_STYPE_DATA1K);
}

static bool off_is_partial_head2(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_STYPE_DATA4K);
}

static bool off_is_partial_leaf(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_STYPE_DATABK);
}

static loff_t off_head1_end_of(size_t slot)
{
	const size_t leaf_size = SILOFS_FILE_HEAD1_LEAF_SIZE;

	return off_end(0, (slot + 1) * leaf_size);
}

static loff_t off_head1_max(void)
{
	return off_head1_end_of(SILOFS_FILE_HEAD1_NLEAF - 1);
}

static loff_t off_head2_end_of(size_t slot)
{
	const size_t leaf_size = SILOFS_FILE_HEAD2_LEAF_SIZE;

	return off_end(off_head1_max(), (slot + 1) * leaf_size);
}

static loff_t off_head2_max(void)
{
	return off_head2_end_of(SILOFS_FILE_HEAD2_NLEAF - 1);
}

static bool off_is_head1(loff_t off)
{
	return off_iswithin(off, 0, off_head1_max());
}

static bool off_is_head2(loff_t off)
{
	return off_iswithin(off, off_head1_max(), off_head2_max());
}

static enum silofs_stype off_to_data_stype(loff_t off)
{
	enum silofs_stype stype;

	if (off < off_head1_max()) {
		stype = SILOFS_STYPE_DATA1K;
	} else if (off < off_head2_max()) {
		stype = SILOFS_STYPE_DATA4K;
	} else {
		stype = SILOFS_STYPE_DATABK;
	}
	return stype;
}

static size_t off_to_head1_slot(loff_t off)
{
	size_t slot;
	const size_t slot_size = SILOFS_FILE_HEAD1_LEAF_SIZE;

	silofs_assert_lt(off, 4 * SILOFS_KILO);
	slot = (size_t)off / slot_size;

	silofs_assert_lt(slot, SILOFS_FILE_HEAD1_NLEAF);
	return slot;
}

static size_t off_to_head2_slot(loff_t off)
{
	const size_t slot_size = SILOFS_FILE_HEAD2_LEAF_SIZE;

	return (size_t)(off - off_head1_max()) / slot_size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool fl_mode_reserve_range(int fl_mode)
{
	const int fl_mask = FALLOC_FL_KEEP_SIZE;

	return (fl_mode & ~fl_mask) == 0;
}

static bool fl_mode_has_mask(int fl_mode, int fl_mask)
{
	return (fl_mode & fl_mask) == fl_mask;
}

static bool fl_mode_keep_size(int fl_mode)
{
	return fl_mode_has_mask(fl_mode, FALLOC_FL_KEEP_SIZE);
}

static bool fl_mode_punch_hole(int fl_mode)
{
	return fl_mode_has_mask(fl_mode, FALLOC_FL_PUNCH_HOLE);
}

static bool fl_mode_zero_range(int fl_mode)
{
	return fl_mode_has_mask(fl_mode, FALLOC_FL_ZERO_RANGE);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void fli_dirtify(struct silofs_fileaf_info *fli,
                        struct silofs_inode_info *ii)
{
	vi_dirtify(&fli->fl_vi, ii);
}

static void fli_incref(struct silofs_fileaf_info *fli)
{
	if (likely(fli != NULL)) {
		vi_incref(&fli->fl_vi);
	}
}

static void fli_decref(struct silofs_fileaf_info *fli)
{
	if (likely(fli != NULL)) {
		vi_decref(&fli->fl_vi);
	}
}

static const struct silofs_vaddr *
fli_vaddr(const struct silofs_fileaf_info *fli)
{
	return (fli != NULL) ? vi_vaddr(&fli->fl_vi) : NULL;
}

static enum silofs_stype fli_stype(const struct silofs_fileaf_info *fli)
{
	return vi_stype(&fli->fl_vi);
}

static size_t fli_data_len(const struct silofs_fileaf_info *fli)
{
	return stype_size(fli_stype(fli));
}

static void *fli_data(const struct silofs_fileaf_info *fli)
{
	void *dat = NULL;
	const enum silofs_stype stype = fli_stype(fli);

	if (stype_isequal(stype, SILOFS_STYPE_DATA1K)) {
		dat = fli->flu.db1;
	} else if (stype_isequal(stype, SILOFS_STYPE_DATA4K)) {
		dat = fli->flu.db4;
	} else if (stype_isequal(stype, SILOFS_STYPE_DATABK)) {
		dat = fli->flu.db;
	} else {
		silofs_panic("illegal file data type: stype=%d", (int)stype);
	}
	return dat;
}

static loff_t fli_off_within(const struct silofs_fileaf_info *fli, loff_t off)
{
	return off_in_data(off, fli_stype(fli));
}

static size_t fli_len_within(const struct silofs_fileaf_info *fli,
                             loff_t off, loff_t end)
{
	return len_of_data(off, end, fli_stype(fli));
}

static bool fli_asyncwr(const struct silofs_fileaf_info *fli)
{
	const struct silofs_uber *uber = vi_uber(&fli->fl_vi);

	return (uber->ub_ctl_flags & SILOFS_UBF_ASYNCWR) > 0;
}

static void fli_pre_io(struct silofs_fileaf_info *fli, int wr_mode)
{
	fli_incref(fli);
	if (wr_mode && fli_asyncwr(fli)) {
		fli->fl_vi.v_asyncwr++;
	}
}

static void fli_post_io(struct silofs_fileaf_info *fli, int wr_mode)
{
	fli_decref(fli);
	if (wr_mode && fli_asyncwr(fli)) {
		silofs_assert_gt(fli->fl_vi.v_asyncwr, 0);
		fli->fl_vi.v_asyncwr--;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t ftn_refcnt(const struct silofs_ftree_node *ftn)
{
	return silofs_le64_to_cpu(ftn->fn_refcnt);
}

static void ftn_set_refcnt(struct silofs_ftree_node *ftn, size_t refcnt)
{
	ftn->fn_refcnt = silofs_cpu_to_le64(refcnt);
}

static void ftn_inc_refcnt(struct silofs_ftree_node *ftn)
{
	ftn_set_refcnt(ftn, ftn_refcnt(ftn) + 1);
}

static void ftn_dec_refcnt(struct silofs_ftree_node *ftn)
{
	const size_t refcnt = ftn_refcnt(ftn);

	silofs_expect_gt(refcnt, 0);
	ftn_set_refcnt(ftn, refcnt - 1);
}

static ino_t ftn_ino(const struct silofs_ftree_node *ftn)
{
	return silofs_ino_to_cpu(ftn->fn_ino);
}

static void ftn_set_ino(struct silofs_ftree_node *ftn, ino_t ino)
{
	ftn->fn_ino = silofs_cpu_to_ino(ino);
}

static loff_t ftn_beg(const struct silofs_ftree_node *ftn)
{
	return silofs_off_to_cpu(ftn->fn_beg);
}

static void ftn_set_beg(struct silofs_ftree_node *ftn, loff_t beg)
{
	ftn->fn_beg = silofs_cpu_to_off(beg);
}

static loff_t ftn_end(const struct silofs_ftree_node *ftn)
{
	return silofs_off_to_cpu(ftn->fn_end);
}

static void ftn_set_end(struct silofs_ftree_node *ftn, loff_t end)
{
	ftn->fn_end = silofs_cpu_to_off(end);
}

static size_t ftn_nchilds_max(const struct silofs_ftree_node *ftn)
{
	return ARRAY_SIZE(ftn->fn_child);
}

static ssize_t ftn_span(const struct silofs_ftree_node *ftn)
{
	return off_len(ftn_beg(ftn), ftn_end(ftn));
}

static size_t ftn_height(const struct silofs_ftree_node *ftn)
{
	return ftn->fn_height;
}

static void ftn_set_height(struct silofs_ftree_node *ftn, size_t height)
{
	ftn->fn_height = (uint8_t)height;
}

static bool ftn_isbottom(const struct silofs_ftree_node *ftn)
{
	const size_t height = ftn_height(ftn);

	silofs_expect_gt(height, 1);
	silofs_expect_le(height, SILOFS_FILE_HEIGHT_MAX);

	return (height == 2);
}

static size_t ftn_nbytes_per_slot(const struct silofs_ftree_node *ftn)
{
	return (size_t)ftn_span(ftn) / ftn_nchilds_max(ftn);
}

static size_t
ftn_slot_by_file_pos(const struct silofs_ftree_node *ftn, loff_t file_pos)
{
	size_t slot;
	ssize_t roff;
	const loff_t span = ftn_span(ftn);
	const size_t nslots = ftn_nchilds_max(ftn);

	roff = off_diff(ftn_beg(ftn), file_pos);
	slot = (size_t)((roff * (long)nslots) / span);

	return slot;
}

static size_t
ftn_height_by_file_pos(const struct silofs_ftree_node *ftn, loff_t off)
{
	size_t height = 1;
	loff_t xlba = off / SILOFS_FILE_TREE_LEAF_SIZE;
	const size_t fm_shift = SILOFS_FILE_MAP_SHIFT;

	STATICASSERT_NELEMS(ftn->fn_child, SILOFS_FILE_NODE_NCHILDS);

	/* TODO: count bits */
	while (xlba > 0) {
		height += 1;
		xlba = (xlba >> fm_shift);
	}
	return height;
}

static loff_t ftn_child(const struct silofs_ftree_node *ftn, size_t slot)
{
	return silofs_vaddr56_parse(&ftn->fn_child[slot]);
}

static void
ftn_set_child(struct silofs_ftree_node *ftn, size_t slot, loff_t off)
{
	silofs_vaddr56_set(&ftn->fn_child[slot], off);
}

static void ftn_reset_child(struct silofs_ftree_node *ftn, size_t slot)
{
	ftn_set_child(ftn, slot, SILOFS_OFF_NULL);
}

static bool ftn_isinrange(const struct silofs_ftree_node *ftn, loff_t pos)
{
	return off_iswithin(pos, ftn_beg(ftn), ftn_end(ftn));
}

static enum silofs_stype ftn_child_stype(const struct silofs_ftree_node *ftn)
{
	return (enum silofs_stype)(ftn->fn_child_stype);
}

static void
ftn_set_child_stype(struct silofs_ftree_node *ftn, enum silofs_stype stype)
{
	ftn->fn_child_stype = (uint8_t)(stype);
}

static void
ftn_child_stype_by_height(const struct silofs_ftree_node *ftn, size_t height,
                          enum silofs_stype *out_child_stype)
{
	if (height <= 2) {
		*out_child_stype = SILOFS_STYPE_DATABK;
	} else {
		*out_child_stype = SILOFS_STYPE_FTNODE;
	}
	silofs_unused(ftn);
}

static loff_t
ftn_span_by_height(const struct silofs_ftree_node *ftn, size_t height)
{
	loff_t span = 0;
	const loff_t bk_size = SILOFS_FILE_TREE_LEAF_SIZE;
	const size_t fm_shift = SILOFS_FILE_MAP_SHIFT;
	const size_t height_max = SILOFS_FILE_HEIGHT_MAX;

	if (likely((height > 1) && (height <= height_max))) {
		span = (bk_size << ((height - 1) * fm_shift));
	}
	silofs_unused(ftn);
	return likely(span) ? span : LONG_MAX; /* make clang-scan happy */
}

static void ftn_calc_range(const struct silofs_ftree_node *ftn,
                           loff_t off, size_t height, loff_t *beg, loff_t *end)
{
	const loff_t span = ftn_span_by_height(ftn, height);

	*beg = off_align(off, span);
	*end = *beg + span;
}

static loff_t ftn_file_pos(const struct silofs_ftree_node *ftn, size_t slot)
{
	loff_t next_off;
	const size_t nbps = ftn_nbytes_per_slot(ftn);

	next_off = off_end(ftn_beg(ftn), slot * nbps);
	return off_align_to_lbk(next_off);
}

static loff_t
ftn_next_file_pos(const struct silofs_ftree_node *ftn, size_t slot)
{
	loff_t file_pos;
	const size_t nbps = ftn_nbytes_per_slot(ftn);

	file_pos = ftn_file_pos(ftn, slot);
	return off_end(file_pos, nbps);
}

static void ftn_clear_childs(struct silofs_ftree_node *ftn)
{
	const size_t nslots_max = ftn_nchilds_max(ftn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		ftn_reset_child(ftn, slot);
	}
}

static void ftn_init(struct silofs_ftree_node *ftn, ino_t ino,
                     loff_t beg, loff_t end, size_t height,
                     enum silofs_stype child_stype)
{
	ftn_set_refcnt(ftn, 0);
	ftn_set_ino(ftn, ino);
	ftn_set_beg(ftn, beg);
	ftn_set_end(ftn, end);
	ftn_set_height(ftn, height);
	ftn_set_child_stype(ftn, child_stype);
	ftn_clear_childs(ftn);
	silofs_memzero(ftn->fn_zeros, sizeof(ftn->fn_zeros));
}

static void ftn_init_by(struct silofs_ftree_node *ftn,
                        ino_t ino, loff_t off, size_t height)
{
	loff_t beg;
	loff_t end;
	enum silofs_stype child_stype;

	ftn_child_stype_by_height(ftn, height, &child_stype);
	ftn_calc_range(ftn, off, height, &beg, &end);
	ftn_init(ftn, ino, beg, end, height, child_stype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_file *ifl_of(const struct silofs_inode *inode)
{
	const struct silofs_inode_file *ifl = &inode->i_sp.f;

	return unconst(ifl);
}

static void ifl_head1_leaf(const struct silofs_inode_file *ifl, size_t slot,
                           struct silofs_vaddr *vaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ifl->f_head1_leaf));

	silofs_vaddr64_parse(&ifl->f_head1_leaf[slot], vaddr);
}

static void ifl_set_head1_leaf(struct silofs_inode_file *ifl, size_t slot,
                               const struct silofs_vaddr *vaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ifl->f_head1_leaf));

	silofs_vaddr64_set(&ifl->f_head1_leaf[slot], vaddr);
}

static void ifl_head2_leaf(const struct silofs_inode_file *ifl, size_t slot,
                           struct silofs_vaddr *vaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ifl->f_head2_leaf));

	silofs_vaddr64_parse(&ifl->f_head2_leaf[slot], vaddr);
}

static void ifl_set_head2_leaf(struct silofs_inode_file *ifl, size_t slot,
                               const struct silofs_vaddr *vaddr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ifl->f_head2_leaf));

	silofs_vaddr64_set(&ifl->f_head2_leaf[slot], vaddr);
}

static size_t ifl_num_head1_leaves(const struct silofs_inode_file *ifl)
{
	return ARRAY_SIZE(ifl->f_head1_leaf);
}

static size_t ifl_num_head2_leaves(const struct silofs_inode_file *ifl)
{
	return ARRAY_SIZE(ifl->f_head2_leaf);
}

static void ifl_tree_root(const struct silofs_inode_file *ifl,
                          struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_parse(&ifl->f_tree_root, vaddr);
}

static void ifl_set_tree_root(struct silofs_inode_file *ifl,
                              const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&ifl->f_tree_root, vaddr);
}

static void ifl_setup(struct silofs_inode_file *ifl)
{
	size_t nslots;
	const struct silofs_vaddr *vaddr = vaddr_none();

	nslots = ifl_num_head1_leaves(ifl);
	for (size_t slot = 0; slot < nslots; ++slot) {
		ifl_set_head1_leaf(ifl, slot, vaddr);
	}
	nslots = ifl_num_head2_leaves(ifl);
	for (size_t slot = 0; slot < nslots; ++slot) {
		ifl_set_head2_leaf(ifl, slot, vaddr);
	}
	ifl_set_tree_root(ifl, vaddr);
}

static struct silofs_inode_file *ii_ifl_of(const struct silofs_inode_info *ii)
{
	return ifl_of(ii->inode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fni_difnify(struct silofs_finode_info *fni,
                        struct silofs_inode_info *ii)
{
	vi_dirtify(&fni->fn_vi, ii);
}

static void fni_incref(struct silofs_finode_info *fni)
{
	if (likely(fni != NULL)) {
		vi_incref(&fni->fn_vi);
	}
}

static void fni_decref(struct silofs_finode_info *fni)
{
	if (likely(fni != NULL)) {
		vi_decref(&fni->fn_vi);
	}
}

static const struct silofs_vaddr *
fni_vaddr(const struct silofs_finode_info *fni)
{
	return vi_vaddr(&fni->fn_vi);
}

static bool
fni_isinrange(const struct silofs_finode_info *fni, loff_t file_pos)
{
	return ftn_isinrange(fni->ftn, file_pos);
}

static bool fni_isbottom(const struct silofs_finode_info *fni)
{
	return ftn_isbottom(fni->ftn);
}

static size_t fni_height(const struct silofs_finode_info *fni)
{
	return ftn_height(fni->ftn);
}

static size_t fni_nchilds_max(const struct silofs_finode_info *fni)
{
	return ftn_nchilds_max(fni->ftn);
}

static size_t
fni_child_slot_of(const struct silofs_finode_info *fni, loff_t off)
{
	return ftn_slot_by_file_pos(fni->ftn, off);
}

static void
fni_assign_child_by_pos(struct silofs_finode_info *parent_fni,
                        loff_t file_pos, const struct silofs_vaddr *vaddr)
{
	size_t child_slot;

	child_slot = fni_child_slot_of(parent_fni, file_pos);
	ftn_set_child(parent_fni->ftn, child_slot, vaddr->off);
}

static void
fni_bind_child(struct silofs_finode_info *parent_fni,
               loff_t file_pos, const struct silofs_vaddr *vaddr)
{
	if (parent_fni != NULL) {
		fni_assign_child_by_pos(parent_fni, file_pos, vaddr);
	}
}

static void fni_bind_finode(struct silofs_finode_info *parent_fni,
                            loff_t file_pos, struct silofs_finode_info *fni)
{
	fni_bind_child(parent_fni, file_pos, fni_vaddr(fni));
	ftn_inc_refcnt(fni->ftn);
}

static void
fni_clear_subtree_mappings(struct silofs_finode_info *fni, size_t slot)
{
	ftn_reset_child(fni->ftn, slot);
}

static void fni_setup(struct silofs_finode_info *fni,
                      const struct silofs_inode_info *ii,
                      loff_t off, size_t height)
{
	ftn_init_by(fni->ftn, ii_ino(ii), off, height);
}

static void fni_resolve_child_by_slot(const struct silofs_finode_info *fni,
                                      size_t slot, struct silofs_vaddr *vaddr)
{
	const struct silofs_ftree_node *rtn = fni->ftn;

	vaddr_setup(vaddr, ftn_child_stype(rtn), ftn_child(rtn, slot));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void *base_of(void *bk_start, loff_t off_in_bk)
{
	return (uint8_t *)bk_start + off_in_bk;
}

static void filc_incref(const struct silofs_file_ctx *f_ctx)
{
	ii_incref(f_ctx->ii);
}

static void filc_decref(const struct silofs_file_ctx *f_ctx)
{
	ii_decref(f_ctx->ii);
}


static void *filc_nil_block(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_lblock *nil_bk = f_ctx->uber->ub.cache->c_nil_lbk;

	return nil_bk->u.bk;
}

static int
filc_iovec_by_alloc(const struct silofs_file_ctx *f_ctx,
                    void *bk_start, loff_t off_in_bk, size_t len,
                    struct silofs_iovec *out_iov)
{
	void *base = base_of(bk_start, off_in_bk);

	return silofs_allocresolve(f_ctx->uber->ub.alloc, base, len, out_iov);
}

static int
filc_iovec_by_fileaf(const struct silofs_file_ctx *f_ctx,
                     struct silofs_fileaf_info *fli, bool all,
                     struct silofs_iovec *out_iov)
{
	void *dat;
	loff_t off_in_bk;
	size_t len;
	int err;

	if (all) {
		off_in_bk = 0;
		len = fli_data_len(fli);
	} else {
		off_in_bk = fli_off_within(fli, f_ctx->off);
		len = fli_len_within(fli, f_ctx->off, f_ctx->end);
	}

	dat = fli_data(fli);
	err = filc_iovec_by_alloc(f_ctx, dat, off_in_bk, len, out_iov);
	if (err) {
		return err;
	}
	out_iov->iov_ref = f_ctx->with_backref ? fli : NULL;
	return 0;
}

static int filc_iovec_by_nilbk(const struct silofs_file_ctx *f_ctx,
                               const enum silofs_stype stype,
                               struct silofs_iovec *out_iov)
{
	void *buf = filc_nil_block(f_ctx);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, stype);

	return filc_iovec_by_alloc(f_ctx, buf, 0, len, out_iov);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_require_mut_vaddr(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	return silofs_require_mut_vaddr(f_ctx->task, vaddr);
}

static size_t filc_io_length(const struct silofs_file_ctx *f_ctx)
{
	return off_ulen(f_ctx->beg, f_ctx->off);
}

static bool filc_has_more_io(const struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->off < f_ctx->end) &&
	       !f_ctx->fm_stop && !f_ctx->task->t_interrupt;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void fpr_reset(struct silofs_fpos_ref *fpr)
{
	memset(fpr, 0, sizeof(*fpr));
	vaddr_reset(&fpr->vaddr);
	oaddr_reset(&fpr->oaddr);
}

static void fpr_setup(struct silofs_fpos_ref *fpr,
                      const struct silofs_file_ctx *f_ctx,
                      struct silofs_finode_info *parent,
                      const struct silofs_vaddr *vaddr, loff_t file_pos)
{
	const bool head1 = off_is_head1(file_pos);
	const bool head2 = off_is_head2(file_pos);
	const bool data = vaddr_isdata(vaddr);
	const bool target = !vaddr_isnull(vaddr);

	memset(fpr, 0, sizeof(*fpr));
	vaddr_assign(&fpr->vaddr, vaddr);
	oaddr_reset(&fpr->oaddr);
	fpr->f_ctx = f_ctx;
	fpr->fni = parent;
	fpr->slot_idx = UINT_MAX;
	fpr->file_pos = file_pos;
	fpr->head1 = head1;
	fpr->head2 = head2;
	fpr->tree = !head1 && !head2;
	fpr->shared = false;
	fpr->has_target = target;
	fpr->has_data = data && target;
	fpr->has_hole = !fpr->has_data;
	fpr->unwritten = true;

	if (head1) {
		fpr->slot_idx = off_to_head1_slot(file_pos);
		fpr->partial = off_is_partial_head1(file_pos, f_ctx->end);
		fpr->leaf = true;
	} else if (head2) {
		fpr->slot_idx = off_to_head2_slot(file_pos);
		fpr->partial = off_is_partial_head2(file_pos, f_ctx->end);
		fpr->leaf = true;
	} else if (parent) {
		fpr->slot_idx = fni_child_slot_of(parent, file_pos);
		fpr->partial = off_is_partial_leaf(file_pos, f_ctx->end);
		fpr->leaf = data;
	} else {
		fpr->slot_idx = 0;
		fpr->partial = false;
		fpr->leaf = false;
	}
}

static void fpr_none(struct silofs_fpos_ref *fpr,
                     const struct silofs_file_ctx *f_ctx,
                     struct silofs_finode_info *parent, loff_t file_pos)
{
	fpr_setup(fpr, f_ctx, parent, vaddr_none(), file_pos);
}

static int fpr_require_mutable(const struct silofs_fpos_ref *fpr)
{
	const struct silofs_vaddr *vaddr = &fpr->vaddr;
	int ret = 0;

	if (!vaddr_isnull(vaddr)) {
		ret = filc_require_mut_vaddr(fpr->f_ctx, vaddr);
	}
	return ret;
}

static int fpr_resolve_oaddr(struct silofs_fpos_ref *fpr)
{
	struct silofs_olink olink;
	int err;

	if (vaddr_isnull(&fpr->vaddr)) {
		return 0;
	}
	err = silofs_resolve_olink_of(fpr->f_ctx->task, &fpr->vaddr,
	                              fpr->f_ctx->stg_mode, &olink);
	if (err) {
		return err;
	}
	oaddr_assign(&fpr->oaddr, &olink.oaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filc_resolve_child_at(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *fni,
                                  loff_t file_pos, size_t slot,
                                  struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;

	fni_resolve_child_by_slot(fni, slot, &vaddr);
	fpr_setup(out_fpr, f_ctx, fni, &vaddr, file_pos);
}

static void filc_resolve_child(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni, loff_t file_pos,
                               struct silofs_fpos_ref *out_fpr)
{
	size_t slot;

	if (fni != NULL) {
		slot = fni_child_slot_of(fni, file_pos);
		filc_resolve_child_at(f_ctx, fni, file_pos, slot, out_fpr);
	} else {
		fpr_setup(out_fpr, f_ctx, NULL, vaddr_none(), file_pos);
	}
}

static bool filc_has_head1_leaves_io(const struct silofs_file_ctx *f_ctx)
{
	return filc_has_more_io(f_ctx) && off_is_head1(f_ctx->off);
}

static bool filc_has_head2_leaves_io(const struct silofs_file_ctx *f_ctx)
{
	return filc_has_more_io(f_ctx) && off_is_head2(f_ctx->off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t filc_head1_leaf_slot_of(const struct silofs_file_ctx *f_ctx)
{
	return off_to_head1_slot(f_ctx->off);
}

static void filc_head1_leaf_at(const struct silofs_file_ctx *f_ctx,
                               size_t slot,
                               struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_head1_leaf(ifl, slot, out_vaddr);
}

static void filc_resolve_head1_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	const size_t slot = filc_head1_leaf_slot_of(f_ctx);

	filc_head1_leaf_at(f_ctx, slot, &vaddr);
	fpr_setup(out_fpr, f_ctx, NULL, &vaddr, f_ctx->off);
}

static void
filc_set_head1_leaf_at(const struct silofs_file_ctx *f_ctx,
                       size_t slot, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_set_head1_leaf(ifl, slot, vaddr);
}

static size_t filc_head2_leaf_slot_of(const struct silofs_file_ctx *f_ctx)
{
	return off_to_head2_slot(f_ctx->off);
}

static void
filc_head2_leaf_at(const struct silofs_file_ctx *f_ctx,
                   size_t slot, struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_head2_leaf(ifl, slot, out_vaddr);
}

static void filc_resolve_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	const size_t slot = filc_head2_leaf_slot_of(f_ctx);

	filc_head2_leaf_at(f_ctx, slot, &vaddr);
	fpr_setup(out_fpr, f_ctx, NULL, &vaddr, f_ctx->off);
}

static void
filc_set_head2_leaf_at(const struct silofs_file_ctx *f_ctx,
                       size_t slot, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_set_head2_leaf(ifl, slot, vaddr);
}

static void filc_tree_root_of(const struct silofs_file_ctx *f_ctx,
                              struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_tree_root(ifl, out_vaddr);
}

static bool filc_has_tree_root(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_vaddr vaddr;

	filc_tree_root_of(f_ctx, &vaddr);
	return stype_isftnode(vaddr.stype);
}

static void filc_set_tree_root_at(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *ifl = ii_ifl_of(f_ctx->ii);

	ifl_set_tree_root(ifl, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t filc_distance_to_next(const struct silofs_file_ctx *f_ctx)
{
	const enum silofs_stype stype = off_to_data_stype(f_ctx->off);

	return len_to_next(f_ctx->off, stype);
}

static void filc_advance_to(struct silofs_file_ctx *f_ctx, loff_t off)
{
	f_ctx->off = off_clamp(f_ctx->off, off, f_ctx->end);
}

static void filc_advance_by_nbytes(struct silofs_file_ctx *f_ctx, size_t len)
{
	silofs_assert_gt(len, 0);
	filc_advance_to(f_ctx, off_end(f_ctx->off, len));
}

static void filc_advance_to_next(struct silofs_file_ctx *f_ctx)
{
	filc_advance_by_nbytes(f_ctx, filc_distance_to_next(f_ctx));
}

static void
filc_advance_to_tree_slot(struct silofs_file_ctx *f_ctx,
                          const struct silofs_finode_info *fni, size_t slt)
{
	filc_advance_to(f_ctx, ftn_file_pos(fni->ftn, slt));
}

static void
filc_advance_to_next_tree_slot(struct silofs_file_ctx *f_ctx,
                               const struct silofs_finode_info *fni,
                               size_t slt)
{
	filc_advance_to(f_ctx, ftn_next_file_pos(fni->ftn, slt));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_check_reg(const struct silofs_file_ctx *f_ctx)
{
	const struct silofs_inode_info *ii = f_ctx->ii;

	if (ii_isdir(ii)) {
		return -SILOFS_EISDIR;
	}
	if (!ii_isreg(ii)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int filc_check_isopen(const struct silofs_file_ctx *f_ctx)
{
	return f_ctx->ii->i_nopen ? 0 : -SILOFS_EBADF;
}

static int filc_check_seek_pos(const struct silofs_file_ctx *f_ctx)
{
	const loff_t isz = ii_size(f_ctx->ii);
	const loff_t pos = f_ctx->off;
	const int whence = f_ctx->whence;

	if ((whence == SEEK_DATA) || (whence == SEEK_HOLE)) {
		if ((pos >= isz) || (pos < 0)) {
			return -SILOFS_ENXIO;
		}
	}
	return 0;
}

static int filc_check_io_range(const struct silofs_file_ctx *f_ctx)
{
	const loff_t off = f_ctx->beg;
	const ssize_t slen = (loff_t)f_ctx->len;
	const ssize_t fsz_max = SILOFS_FILE_SIZE_MAX;

	if (off < 0) {
		return -SILOFS_EINVAL;
	}
	if (off > fsz_max) {
		return -SILOFS_EFBIG;
	}
	if (slen > fsz_max) {
		return -SILOFS_EINVAL;
	}
	if ((off + slen) < off) {
		return -SILOFS_EOVERFLOW;
	}
	return 0;
}

static int filc_check_io_end(const struct silofs_file_ctx *f_ctx)
{
	const loff_t end = f_ctx->end;
	const ssize_t fsz_max = SILOFS_FILE_SIZE_MAX;

	if (end < 0) {
		return -SILOFS_EINVAL;
	}
	if (end > fsz_max) {
		return -SILOFS_EFBIG;
	}
	return 0;
}

static int filc_check_file_io(const struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_reg(f_ctx);
	if (err) {
		return err;
	}
	err = filc_check_isopen(f_ctx);
	if (err && (f_ctx->op_mask & ~OP_TRUNC)) {
		return err;
	}
	err = filc_check_io_range(f_ctx);
	if (err) {
		return err;
	}
	if (f_ctx->op_mask & (OP_WRITE | OP_FALLOC)) {
		err = filc_check_io_end(f_ctx);
		if (err) {
			return err;
		}
	}
	if (f_ctx->op_mask & (OP_READ | OP_WRITE)) {
		if (f_ctx->len > SILOFS_IO_SIZE_MAX) {
			return -SILOFS_EINVAL;
		}
		if (!f_ctx->rwi_ctx) {
			return -SILOFS_EINVAL;
		}
	}
	if (f_ctx->op_mask & OP_LSEEK) {
		err = filc_check_seek_pos(f_ctx);
		if (err) {
			return err;
		}
	}
	if (f_ctx->op_mask & OP_COPY_RANGE) {
		if (f_ctx->cp_flags != 0) {
			return -SILOFS_EINVAL;
		}
		if (!off_is_bk_aligned(f_ctx->beg) &&
		    (f_ctx->len > SILOFS_IO_SIZE_MAX)) {
			return -SILOFS_EINVAL;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni,
                                    struct silofs_fpos_ref *out_fpr);

static bool filc_ismapping_boundaries(const struct silofs_file_ctx *f_ctx)
{
	const loff_t mapping_size =
	        (SILOFS_FILE_TREE_LEAF_SIZE * SILOFS_FILE_NODE_NCHILDS);

	return ((f_ctx->off % mapping_size) == 0);
}

static void
filc_update_post_io(const struct silofs_file_ctx *f_ctx,  bool kill_suid_sgid)
{
	struct silofs_iattr iattr;
	struct silofs_inode_info *ii = f_ctx->ii;
	const loff_t isz = ii_size(ii);
	const loff_t isp = ii_span(ii);
	const loff_t off = f_ctx->off;
	const loff_t end = f_ctx->end;
	const size_t len = filc_io_length(f_ctx);

	silofs_iattr_setup(&iattr, ii_ino(ii));
	if (f_ctx->op_mask & OP_READ) {
		iattr.ia_flags |= SILOFS_IATTR_ATIME | SILOFS_IATTR_LAZY;
	} else if (f_ctx->op_mask & (OP_WRITE | OP_COPY_RANGE)) {
		iattr.ia_flags |= SILOFS_IATTR_SIZE | SILOFS_IATTR_SPAN;
		iattr.ia_size = off_max(off, isz);
		iattr.ia_span = off_max(off, isp);
		if (len > 0) {
			iattr.ia_flags |= SILOFS_IATTR_MCTIME;
			if (kill_suid_sgid) {
				iattr.ia_flags |= SILOFS_IATTR_KILL_SUID;
				iattr.ia_flags |= SILOFS_IATTR_KILL_SGID;
			}
		}
	} else if (f_ctx->op_mask & OP_FALLOC) {
		iattr.ia_flags |= SILOFS_IATTR_MCTIME | SILOFS_IATTR_SPAN;
		iattr.ia_span = off_max(end, isp);
		if (!fl_mode_keep_size(f_ctx->fl_mode)) {
			iattr.ia_flags |= SILOFS_IATTR_SIZE;
			iattr.ia_size = off_max(end, isz);
		}
	} else if (f_ctx->op_mask & OP_TRUNC) {
		iattr.ia_flags |= SILOFS_IATTR_SIZE | SILOFS_IATTR_SPAN;
		iattr.ia_size = f_ctx->beg;
		iattr.ia_span = f_ctx->beg;
		if (isz != f_ctx->beg) {
			iattr.ia_flags |= SILOFS_IATTR_MCTIME;
			if (kill_suid_sgid) {
				iattr.ia_flags |= SILOFS_IATTR_KILL_SUID;
				iattr.ia_flags |= SILOFS_IATTR_KILL_SGID;
			}
		}
	}
	ii_update_iattrs(ii, &f_ctx->task->t_oper.op_creds, &iattr);
}

static int fpr_update_unwritten(struct silofs_fpos_ref *fpr)
{
	const struct silofs_vaddr *vaddr = &fpr->vaddr;
	struct silofs_task *task = fpr->f_ctx->task;

	fpr->unwritten = true;
	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	return silofs_test_unwritten_at(task, vaddr, &fpr->unwritten);
}

static void fpr_update_partial(struct silofs_fpos_ref *fpr, size_t len)
{
	if (len > 0) {
		if (fpr->head1) {
			fpr->partial = (len < SILOFS_FILE_HEAD1_LEAF_SIZE);
		} else if (fpr->head2) {
			fpr->partial = (len < SILOFS_FILE_HEAD2_LEAF_SIZE);
		} else {
			silofs_assert(fpr->tree);
			fpr->partial = (len < SILOFS_FILE_TREE_LEAF_SIZE);
		}
	}
}

static int fpr_update_pre_write_leaf(struct silofs_fpos_ref *fpr, size_t len)
{
	fpr_update_partial(fpr, len);
	return fpr_update_unwritten(fpr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_recheck_fileaf(const struct silofs_file_ctx *f_ctx,
                               struct silofs_fileaf_info *fli)
{
	if (fli->fl_vi.v.flags & SILOFS_LNF_RECHECK) {
		return 0;
	}
	silofs_unused(f_ctx);
	fli->fl_vi.v.flags |= SILOFS_LNF_RECHECK;
	return 0;
}

static int filc_stage_fileaf(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_fileaf_info **out_fli)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_fileaf_info *fli = NULL;
	int err;

	err = silofs_stage_vnode(f_ctx->task, f_ctx->ii, vaddr,
	                         f_ctx->stg_mode, &vi);
	if (err) {
		return err;
	}
	fli = silofs_fli_from_vi(vi);
	silofs_fli_rebind_view(fli);
	err = filc_recheck_fileaf(f_ctx, fli);
	if (err) {
		return err;
	}
	*out_fli = fli;
	return 0;
}

static void filc_dirtify_fileaf(const struct silofs_file_ctx *f_ctx,
                                struct silofs_fileaf_info *fli)
{
	fli_dirtify(fli, f_ctx->ii);
}

static void filc_zero_fileaf_sub(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_fileaf_info *fli,
                                 loff_t off_in_db, size_t len)
{
	struct silofs_data_block64 *db = fli->flu.db;

	silofs_memzero(&db->dat[off_in_db], len);
	filc_dirtify_fileaf(f_ctx, fli);
}

static int
filc_zero_data_leaf_range(const struct silofs_file_ctx *f_ctx,
                          const struct silofs_vaddr *vaddr,
                          loff_t off_in_bk, size_t len)
{
	struct silofs_fileaf_info *fli = NULL;
	int err;

	err = filc_stage_fileaf(f_ctx, vaddr, &fli);
	if (err) {
		return err;
	}
	filc_zero_fileaf_sub(f_ctx, fli, off_in_bk, len);
	return 0;
}

static int filc_zero_data_leaf_at(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	return filc_zero_data_leaf_range(f_ctx, vaddr, 0, vaddr->len);
}

static int fpr_stage_fileaf_at(const struct silofs_fpos_ref *fpr,
                               struct silofs_fileaf_info **out_fli)
{
	int ret = -SILOFS_ENOENT;

	*out_fli = NULL;
	if (fpr->has_data) {
		ret = filc_stage_fileaf(fpr->f_ctx, &fpr->vaddr, out_fli);
	}
	return ret;
}

static int filc_recheck_finode(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni)
{
	const ino_t r_ino = ftn_ino(fni->ftn);
	const ino_t f_ino = ii_ino(f_ctx->ii);
	const size_t height = ftn_height(fni->ftn);

	if (fni->fn_vi.v.flags & SILOFS_LNF_RECHECK) {
		return 0;
	}
	if ((height < 2) || (height > 16)) {
		log_err("illegal height: height=%lu ino=%lu", height, f_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	/* TODO: refine me when having FICLONE + meta-data */
	if (r_ino != f_ino) {
		log_err("bad finode ino: r_ino=%lu f_ino=%lu", r_ino, f_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	fni->fn_vi.v.flags |= SILOFS_LNF_RECHECK;
	return 0;
}

static int filc_stage_finode(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_finode_info **out_fni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_finode_info *fni = NULL;
	int err;

	err = silofs_stage_vnode(f_ctx->task, f_ctx->ii, vaddr,
	                         f_ctx->stg_mode, &vi);
	if (err) {
		return err;
	}
	fni = silofs_fni_from_vi(vi);
	silofs_fni_rebind_view(fni);
	err = filc_recheck_finode(f_ctx, fni);
	if (err) {
		return err;
	}
	*out_fni = fni;
	return 0;
}

static int filc_stage_tree_root(const struct silofs_file_ctx *f_ctx,
                                struct silofs_finode_info **out_fni)
{
	struct silofs_vaddr root_vaddr;

	filc_tree_root_of(f_ctx, &root_vaddr);
	return filc_stage_finode(f_ctx, &root_vaddr, out_fni);
}

static size_t filc_iter_start_slot(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_finode_info *parent_fni)
{
	return fni_child_slot_of(parent_fni, f_ctx->off);
}

static bool filc_is_seek_data(const struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->whence == SEEK_DATA);
}

static bool filc_is_seek_hole(const struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->whence == SEEK_HOLE);
}

static int filc_seek_tree_at_leaves(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni,
                                    struct silofs_fpos_ref *out_fpr)
{
	size_t start_slot;
	size_t nslots_max;
	const bool seek_hole = filc_is_seek_hole(f_ctx);

	start_slot = filc_iter_start_slot(f_ctx, parent_fni);
	nslots_max = fni_nchilds_max(parent_fni);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		filc_advance_to_tree_slot(f_ctx, parent_fni, slot);
		if (!filc_has_more_io(f_ctx)) {
			break;
		}
		filc_resolve_child_at(f_ctx, parent_fni, f_ctx->off,
		                      slot, out_fpr);
		if (seek_hole == out_fpr->has_hole) {
			return 0;
		}
	}
	return -SILOFS_ENOENT;
}

static int
filc_seek_tree_recursive_at(struct silofs_file_ctx *f_ctx,
                            struct silofs_finode_info *parent_fni, size_t slot,
                            struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	struct silofs_finode_info *fni = NULL;
	int err;

	fni_resolve_child_by_slot(parent_fni, slot, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_finode(f_ctx, &vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_seek_tree_recursive(f_ctx, fni, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni,
                                    struct silofs_fpos_ref *out_fpr)
{
	size_t start_slot;
	const size_t nslots_max = fni_nchilds_max(parent_fni);
	int ret;

	fni_incref(parent_fni);
	if (!fni_isinrange(parent_fni, f_ctx->off)) {
		ret = -SILOFS_ENOENT;
		goto out;
	}
	if (fni_isbottom(parent_fni)) {
		ret = filc_seek_tree_at_leaves(f_ctx, parent_fni, out_fpr);
		goto out;
	}
	ret = filc_is_seek_hole(f_ctx) ? 0 : -SILOFS_ENOENT;
	start_slot = fni_child_slot_of(parent_fni, f_ctx->off);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		ret = filc_seek_tree_recursive_at(f_ctx, parent_fni,
		                                  slot, out_fpr);
		if (ret != -SILOFS_ENOENT) {
			goto out;
		}
		filc_advance_to_next_tree_slot(f_ctx, parent_fni, slot);
	}
out:
	fni_decref(parent_fni);
	return ret;
}

static int filc_seek_by_tree_map(struct silofs_file_ctx *f_ctx,
                                 struct silofs_fpos_ref *out_fpr)
{
	struct silofs_finode_info *root_fni = NULL;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_root(f_ctx, &root_fni);
	if (err) {
		return err;
	}
	err = filc_seek_tree_recursive(f_ctx, root_fni, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_seek_data_by_head_leaves(struct silofs_file_ctx *f_ctx,
                struct silofs_fpos_ref *out_fpr)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fpr);
		if (out_fpr->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fpr);
		if (out_fpr->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int
filc_seek_hole_by_head_leaves(struct silofs_file_ctx *f_ctx,
                              struct silofs_fpos_ref *out_fpr)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fpr);
		if (out_fpr->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fpr);
		if (out_fpr->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_resolve_iovec(const struct silofs_file_ctx *f_ctx,
                              struct silofs_fileaf_info *fli,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_iovec *out_iov)
{
	enum silofs_stype stype;
	int err;

	if (fli != NULL) {
		err = filc_iovec_by_fileaf(f_ctx, fli, false, out_iov);
	} else {
		stype = off_to_data_stype(f_ctx->off);
		silofs_assert((vaddr == NULL) || (stype == vaddr->stype));
		err = filc_iovec_by_nilbk(f_ctx, stype, out_iov);
	}
	return err;
}

static void iovref_pre(const struct silofs_iovec *iov, int wr_mode)
{
	struct silofs_fileaf_info *fli = iov->iov_ref;

	if (fli != NULL) {
		fli_pre_io(fli, wr_mode);
	}
}

static void iovref_post(const struct silofs_iovec *iov, int wr_mode)
{
	struct silofs_fileaf_info *fli = iov->iov_ref;

	if (fli != NULL) {
		fli_post_io(fli, wr_mode);
	}
}

static int filc_call_rw_actor(const struct silofs_file_ctx *f_ctx,
                              struct silofs_fileaf_info *fli,
                              const struct silofs_vaddr *vaddr,
                              size_t *out_len)
{
	struct silofs_iovec iov = {
		.iov_ref = NULL,
		.iov_base = NULL,
		.iov_off = -1,
		.iov_len = 0,
		.iov_fd = -1,
	};
	int wr_mode = f_ctx->op_mask & OP_WRITE;
	int err;

	*out_len = 0;
	err = filc_resolve_iovec(f_ctx, fli, vaddr, &iov);
	if (err) {
		return err;
	}
	iovref_pre(&iov, wr_mode);
	err = f_ctx->rwi_ctx->actor(f_ctx->rwi_ctx, &iov);
	*out_len = iov.iov_len;
	if (err) {
		iovref_post(&iov, wr_mode);
		return err;
	}
	return 0;
}

static int
filc_export_data_by_fileaf(const struct silofs_file_ctx *f_ctx,
                           struct silofs_fileaf_info *fli, size_t *out_sz)
{
	return filc_call_rw_actor(f_ctx, fli, fli_vaddr(fli), out_sz);
}

static int filc_export_data_by_vaddr(struct silofs_file_ctx *f_ctx,
                                     const struct silofs_vaddr *vaddr,
                                     size_t *out_size)
{
	return filc_call_rw_actor(f_ctx, NULL, vaddr, out_size);
}

static int
filc_import_data_by_fileaf(const struct silofs_file_ctx *f_ctx,
                           struct silofs_fileaf_info *fli, size_t *out_sz)
{
	int err;

	err = filc_call_rw_actor(f_ctx, fli, fli_vaddr(fli), out_sz);
	if (!err) {
		filc_dirtify_fileaf(f_ctx, fli);
	}
	return err;
}

static void filc_child_of_current_pos(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni,
                                      struct silofs_fpos_ref *out_fpr)
{
	filc_resolve_child(f_ctx, parent_fni, f_ctx->off, out_fpr);
}

static void filc_resolve_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_finode_info *parent_fni,
                                   struct silofs_fpos_ref *out_fpr)
{
	filc_child_of_current_pos(f_ctx, parent_fni, out_fpr);
}

static void filc_resolve_curr_node(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_finode_info *parent_fni,
                                   struct silofs_fpos_ref *out_fpr)
{
	filc_child_of_current_pos(f_ctx, parent_fni, out_fpr);
}

static int filc_stage_by_tree_map(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info **out_fni)
{
	struct silofs_fpos_ref fpr = { .file_pos = -1 };
	struct silofs_finode_info *fni = NULL;
	size_t height;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	if (!fni_isinrange(fni, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}
	height = fni_height(fni);
	while (height--) {
		if (fni_isbottom(fni)) {
			*out_fni = fni;
			return 0;
		}
		filc_resolve_curr_node(f_ctx, fni, &fpr);
		err = filc_stage_finode(f_ctx, &fpr.vaddr, &fni);
		if (err) {
			return err;
		}
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_read_leaf_by_copy(struct silofs_file_ctx *f_ctx,
                                  struct silofs_fileaf_info *fli, size_t *sz)
{
	int err;

	fli_incref(fli);
	err = filc_export_data_by_fileaf(f_ctx, fli, sz);
	fli_decref(fli);
	return err;
}

static int
filc_read_leaf_as_zeros(struct silofs_file_ctx *f_ctx, size_t *out_sz)
{
	return filc_export_data_by_vaddr(f_ctx, NULL, out_sz);
}

static int
filc_read_from_leaf(struct silofs_file_ctx *f_ctx,
                    struct silofs_fpos_ref *fpr, size_t *out_len)
{
	struct silofs_fileaf_info *fli = NULL;
	int err;

	*out_len = 0;
	err = fpr_update_unwritten(fpr);
	if (err) {
		return err;
	}
	if (fpr->unwritten) {
		err = filc_read_leaf_as_zeros(f_ctx, out_len);
		if (err) {
			return err;
		}
	} else {
		err = fpr_stage_fileaf_at(fpr, &fli);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		err = filc_read_leaf_by_copy(f_ctx, fli, out_len);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
filc_do_read_from_tree_leaves(struct silofs_file_ctx *f_ctx,
                              struct silofs_finode_info *parent_fni)
{
	struct silofs_fpos_ref fpr;
	size_t len = 0;
	int err;

	while (filc_has_more_io(f_ctx)) {
		filc_resolve_tree_leaf(f_ctx, parent_fni, &fpr);
		err = filc_read_from_leaf(f_ctx, &fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int filc_read_from_tree_leaves(struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_read_from_tree_leaves(f_ctx, parent_fni);
	fni_decref(parent_fni);

	return ret;
}

static int filc_read_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *parent_fni = NULL;
	int err;

	while (filc_has_more_io(f_ctx)) {
		parent_fni = NULL;
		err = filc_stage_by_tree_map(f_ctx, &parent_fni);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		err = filc_read_from_tree_leaves(f_ctx, parent_fni);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int filc_read_by_head_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	size_t len;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, &fpr);
		err = filc_read_from_leaf(f_ctx, &fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, &fpr);
		err = filc_read_from_leaf(f_ctx, &fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_read_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_read_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_read_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

struct silofs_read_iter {
	struct silofs_rwiter_ctx rwi;
	uint8_t *dat;
	size_t dat_len;
	size_t dat_max;
};

static struct silofs_read_iter *
read_iter_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_read_iter *rdi =
	        container_of2(rwi, struct silofs_read_iter, rwi);

	return unconst(rdi);
}

static int read_iter_actor(struct silofs_rwiter_ctx *rwi,
                           const struct silofs_iovec *iov)
{
	struct silofs_read_iter *rdi = read_iter_of(rwi);
	int err;

	if ((iov->iov_fd > 0) && (iov->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if ((rdi->dat_len + iov->iov_len) > rdi->dat_max) {
		return -SILOFS_EINVAL;
	}
	err = silofs_iovec_copy_into(iov, rdi->dat + rdi->dat_len);
	if (err) {
		return err;
	}
	rdi->dat_len += iov->iov_len;
	return 0;
}

static loff_t rw_iter_end(const struct silofs_rwiter_ctx *rwi)
{
	return off_end(rwi->off, rwi->len);
}

static void filc_update_with_rw_iter(struct silofs_file_ctx *f_ctx,
                                     struct silofs_rwiter_ctx *rwi_ctx)
{
	const loff_t end = rw_iter_end(rwi_ctx);
	const loff_t isz = ii_size(f_ctx->ii);

	f_ctx->rwi_ctx = rwi_ctx;
	f_ctx->len = rwi_ctx->len;
	f_ctx->beg = rwi_ctx->off;
	f_ctx->off = rwi_ctx->off;
	if (f_ctx->op_mask & OP_READ) {
		f_ctx->end = off_min(end, isz);
	} else {
		f_ctx->end = end;
	}
}

static int filc_read_iter(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (!err) {
		err = filc_read_data(f_ctx);
		filc_update_post_io(f_ctx, false);
	}
	return err;
}

int silofs_do_read_iter(struct silofs_task *task, struct silofs_inode_info *ii,
                        struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 1,
		.stg_mode = SILOFS_STG_CUR,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, rwi);
	filc_incref(&f_ctx);
	ret = filc_read_iter(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

int silofs_do_read(struct silofs_task *task, struct silofs_inode_info *ii,
                   void *buf, size_t len, loff_t off, size_t *out_len)
{
	struct silofs_read_iter rdi = {
		.dat_len = 0,
		.rwi.actor = read_iter_actor,
		.rwi.len = len,
		.rwi.off = off,
		.dat = buf,
		.dat_max = len,
	};
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 0,
		.stg_mode = SILOFS_STG_CUR,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, &rdi.rwi);
	filc_incref(&f_ctx);
	ret = filc_read_iter(&f_ctx);
	filc_decref(&f_ctx);
	*out_len = rdi.dat_len;
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_clear_unwritten_at(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	return silofs_clear_unwritten_at(f_ctx->task, vaddr);
}

static int filc_clear_unwritten_of(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_info *fli)
{
	const struct silofs_vaddr *vaddr = fli_vaddr(fli);
	int ret;

	fli_incref(fli);
	ret = filc_clear_unwritten_at(f_ctx, vaddr);
	if (ret == 0) {
		filc_dirtify_fileaf(f_ctx, fli);
	}
	fli_decref(fli);
	return ret;
}

static int filc_claim_vspace(const struct silofs_file_ctx *f_ctx,
                             enum silofs_stype stype,
                             struct silofs_vaddr *out_vaddr)
{
	return silofs_claim_vspace(f_ctx->task, stype, out_vaddr);
}

static int filc_claim_data_space(const struct silofs_file_ctx *f_ctx,
                                 enum silofs_stype stype,
                                 struct silofs_vaddr *out_vaddr)
{
	int err;

	err = filc_claim_vspace(f_ctx, stype, out_vaddr);
	if (err) {
		return err;
	}
	err = filc_require_mut_vaddr(f_ctx, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_share_data_space(const struct silofs_file_ctx *f_ctx,
                                 const struct silofs_vaddr *vaddr)
{
	return silofs_addref_vspace(f_ctx->task, vaddr);
}

static int filc_reclaim_data_space(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	return silofs_reclaim_vspace(f_ctx->task, vaddr);
}

static int filc_del_data_space(const struct silofs_file_ctx *f_ctx,
                               const struct silofs_vaddr *vaddr)
{
	int err;
	bool last = false;

	err = silofs_test_last_allocated(f_ctx->task, vaddr, &last);
	if (err) {
		return err;
	}
	if (last || !vaddr_isdatabk(vaddr)) {
		err = filc_clear_unwritten_at(f_ctx, vaddr);
		if (err) {
			return err;
		}
	}
	err = silofs_remove_vnode_of(f_ctx->task, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_spawn_finode(const struct silofs_file_ctx *f_ctx,
                             struct silofs_finode_info **out_fni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_finode_info *fni = NULL;
	int err;

	err = silofs_spawn_vnode_of(f_ctx->task, f_ctx->ii,
	                            SILOFS_STYPE_FTNODE, &vi);
	if (err) {
		return err;
	}
	fni = silofs_fni_from_vi(vi);
	silofs_fni_rebind_view(fni);
	fni_difnify(fni, f_ctx->ii);
	*out_fni = fni;
	return 0;
}

static int filc_remove_finode(const struct silofs_file_ctx *f_ctx,
                              struct silofs_finode_info *fni)
{
	return silofs_remove_vnode_by(f_ctx->task, &fni->fn_vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fpr_update_head1_leaf(const struct silofs_fpos_ref *fpr)
{
	filc_set_head1_leaf_at(fpr->f_ctx, fpr->slot_idx, &fpr->vaddr);
	ii_dirtify(fpr->f_ctx->ii);
}

static void fpr_update_head2_leaf(const struct silofs_fpos_ref *fpr)
{
	filc_set_head2_leaf_at(fpr->f_ctx, fpr->slot_idx, &fpr->vaddr);
	ii_dirtify(fpr->f_ctx->ii);
}

static void filc_update_tree_root(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	filc_set_tree_root_at(f_ctx, vaddr);
	ii_dirtify(f_ctx->ii);
}

static void
filc_update_iattr_blocks(const struct silofs_file_ctx *f_ctx,
                         const struct silofs_vaddr *vaddr, long dif)
{
	const struct silofs_creds *creds = &f_ctx->task->t_oper.op_creds;

	ii_update_iblocks(f_ctx->ii, creds, vaddr->stype, dif);
}

static int filc_spawn_setup_finode(const struct silofs_file_ctx *f_ctx,
                                   loff_t off, size_t height,
                                   struct silofs_finode_info **out_fni)
{
	int err;

	err = filc_spawn_finode(f_ctx, out_fni);
	if (err) {
		return err;
	}
	fni_setup(*out_fni, f_ctx->ii, off, height);
	fni_difnify(*out_fni, f_ctx->ii);
	return 0;
}

static int
filc_spawn_root_finode(const struct silofs_file_ctx *f_ctx,
                       size_t height, struct silofs_finode_info **out_fni)
{
	silofs_assert_gt(height, 0);

	return filc_spawn_setup_finode(f_ctx, 0, height, out_fni);
}

static int filc_spawn_bind_finode(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *parent_fni,
                                  struct silofs_finode_info **out_fni)
{
	const loff_t file_pos = f_ctx->off;
	const size_t height = fni_height(parent_fni);
	int err;

	err = filc_spawn_setup_finode(f_ctx, file_pos, height - 1, out_fni);
	if (err) {
		return err;
	}
	fni_bind_finode(parent_fni, file_pos, *out_fni);
	fni_difnify(parent_fni, f_ctx->ii);
	return 0;
}

static int filc_create_data_leaf(const struct silofs_file_ctx *f_ctx,
                                 enum silofs_stype stype,
                                 struct silofs_vaddr *out_vaddr)
{
	int err;

	err = filc_claim_data_space(f_ctx, stype, out_vaddr);
	if (err) {
		return err;
	}
	filc_update_iattr_blocks(f_ctx, out_vaddr, 1);
	return 0;
}

static int filc_create_head1_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_STYPE_DATA1K, &vaddr);
	if (err) {
		return err;
	}
	fpr_setup(out_fpr, f_ctx, NULL, &vaddr, f_ctx->off);
	fpr_update_head1_leaf(out_fpr);
	return 0;
}

static int filc_create_head2_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_STYPE_DATA4K, &vaddr);
	if (err) {
		return err;
	}
	fpr_setup(out_fpr, f_ctx, NULL, &vaddr, f_ctx->off);
	fpr_update_head2_leaf(out_fpr);
	return 0;
}

static int
filc_do_create_tree_leaf_space(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_STYPE_DATABK, &vaddr);
	if (err) {
		return err;
	}
	fni_bind_child(parent_fni, f_ctx->off, &vaddr);
	fni_difnify(parent_fni, f_ctx->ii);
	return 0;
}

static int filc_create_tree_leaf_space(const struct silofs_file_ctx *f_ctx,
                                       struct silofs_finode_info *parent_fni)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_create_tree_leaf_space(f_ctx, parent_fni);
	fni_decref(parent_fni);
	return ret;
}

static void filc_bind_sub_tree(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni)
{
	struct silofs_vaddr vaddr;

	filc_tree_root_of(f_ctx, &vaddr);
	ftn_set_child(fni->ftn, 0, vaddr.off);
	fni_difnify(fni, f_ctx->ii);

	filc_update_tree_root(f_ctx, fni_vaddr(fni));
	fni_bind_finode(NULL, 0, fni);
}

static size_t off_to_height(loff_t off)
{
	return ftn_height_by_file_pos(NULL, off);
}

static int filc_resolve_tree_root(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info **out_fni)
{
	return filc_has_tree_root(f_ctx) ?
	       filc_stage_tree_root(f_ctx, out_fni) : 0;
}

static int filc_create_tree_spine(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *fni = NULL;
	size_t new_height;
	size_t cur_height;
	int err;

	err = filc_resolve_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	cur_height = fni ? fni_height(fni) : 1;
	new_height = off_to_height(f_ctx->off);
	while (new_height > cur_height) {
		err = filc_spawn_root_finode(f_ctx, ++cur_height, &fni);
		if (err) {
			return err;
		}
		filc_bind_sub_tree(f_ctx, fni);
	}
	return 0;
}

static int filc_require_finode(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni,
                               struct silofs_finode_info **out_fni)
{
	struct silofs_fpos_ref fpr;
	int ret;

	fni_incref(parent_fni);
	filc_resolve_curr_node(f_ctx, parent_fni, &fpr);
	if (fpr.has_target) {
		ret = filc_stage_finode(f_ctx, &fpr.vaddr, out_fni);
	} else {
		ret = filc_spawn_bind_finode(f_ctx, parent_fni, out_fni);
	}
	fni_decref(parent_fni);
	return ret;
}

static int filc_require_tree_path(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info **out_fni)
{
	struct silofs_finode_info *fni;
	size_t height;
	int err;

	*out_fni = NULL;
	err = filc_stage_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	height = fni_height(fni);
	for (size_t level = height; level > 0; --level) {
		if (fni_isbottom(fni)) {
			*out_fni = fni;
			return 0;
		}
		err = filc_require_finode(f_ctx, fni, &fni);
		if (err) {
			return err;
		}
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_require_tree(const struct silofs_file_ctx *f_ctx,
                             struct silofs_finode_info **out_fni)
{
	int err;

	err = filc_create_tree_spine(f_ctx);
	if (err) {
		return err;
	}
	err = filc_require_tree_path(f_ctx, out_fni);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_do_write_leaf_by_copy(const struct silofs_file_ctx *f_ctx,
                           struct silofs_fileaf_info *fli, size_t *out_sz)
{
	int err;

	err = filc_import_data_by_fileaf(f_ctx, fli, out_sz);
	if (err) {
		return err;
	}
	err = filc_clear_unwritten_of(f_ctx, fli);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_write_leaf_by_copy(const struct silofs_file_ctx *f_ctx,
                        struct silofs_fileaf_info *fli, size_t *out_sz)
{
	int err;

	fli_incref(fli);
	err = filc_do_write_leaf_by_copy(f_ctx, fli, out_sz);
	fli_decref(fli);
	return err;
}

static int
filc_pre_write_leaf(const struct silofs_file_ctx *f_ctx,
                    struct silofs_fpos_ref *fpr, size_t len)
{
	int err;

	err = fpr_update_pre_write_leaf(fpr, len);
	if (err) {
		return err;
	}
	if (!fpr->unwritten || !fpr->partial) {
		return 0;
	}
	err = filc_zero_data_leaf_at(f_ctx, &fpr->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_do_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                          struct silofs_finode_info *parent_fni,
                          struct silofs_fpos_ref *out_fpr)
{
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fni, out_fpr);
	if (out_fpr->has_data) {
		return fpr_require_mutable(out_fpr);
	}
	err = filc_create_tree_leaf_space(f_ctx, parent_fni);
	if (err) {
		return err;
	}
	filc_resolve_tree_leaf(f_ctx, parent_fni, out_fpr);
	return 0;
}

static int filc_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *parent_fni,
                                  struct silofs_fpos_ref *out_fpr)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_require_tree_leaf(f_ctx, parent_fni, out_fpr);
	fni_decref(parent_fni);
	return ret;
}

static int
fpr_write_to_leaf(struct silofs_fpos_ref *fpr, size_t *out_len)
{
	struct silofs_fileaf_info *fli = NULL;
	int err;

	err = filc_pre_write_leaf(fpr->f_ctx, fpr, 0);
	if (err) {
		return err;
	}
	err = fpr_stage_fileaf_at(fpr, &fli);
	if (err) {
		return err;
	}
	err = filc_write_leaf_by_copy(fpr->f_ctx, fli, out_len);
	if (err) {
		return err;
	}
	fpr->unwritten = false;
	return 0;
}

static int fpr_detect_shared(struct silofs_fpos_ref *fpr)
{
	struct silofs_task *task = fpr->f_ctx->task;
	const struct silofs_vaddr *vaddr = &fpr->vaddr;
	int ret = 0;

	if (fpr->tree && fpr->has_data && !fpr->shared) {
		ret = silofs_test_shared_dbkref(task, vaddr, &fpr->shared);
	}
	return ret;
}

static int
filc_do_write_to_tree_leaves(struct silofs_file_ctx *f_ctx,
                             struct silofs_finode_info *parent_fni)
{
	struct silofs_fpos_ref fpr = { .file_pos = -1 };
	size_t len;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_require_tree_leaf(f_ctx, parent_fni, &fpr);
		if (err) {
			return err;
		}
		err = fpr_detect_shared(&fpr);
		if (err) {
			return err;
		}
		err = fpr_unshare_leaf(&fpr);
		if (err) {
			return err;
		}
		len = 0;
		err = fpr_write_to_leaf(&fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int filc_write_to_tree_leaves(struct silofs_file_ctx *f_ctx,
                                     struct silofs_finode_info *parent_fni)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_write_to_tree_leaves(f_ctx, parent_fni);
	fni_decref(parent_fni);
	return ret;
}

static int filc_write_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_require_tree(f_ctx, &fni);
		if (err) {
			return err;
		}
		err = filc_write_to_tree_leaves(f_ctx, fni);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int filc_require_head1_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fpos_ref *out_fpr)
{
	int err;

	filc_resolve_head1_leaf(f_ctx, out_fpr);
	if (out_fpr->has_data) {
		return fpr_require_mutable(out_fpr);
	}
	err = filc_create_head1_leaf_space(f_ctx, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_require_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fpos_ref *out_fpr)
{
	int err;

	filc_resolve_head2_leaf(f_ctx, out_fpr);
	if (out_fpr->has_data) {
		return fpr_require_mutable(out_fpr);
	}
	err = filc_create_head2_leaf_space(f_ctx, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_write_by_head_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	size_t len = 0;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		err = filc_require_head1_leaf(f_ctx, &fpr);
		if (err) {
			return err;
		}
		len = 0;
		err = fpr_write_to_leaf(&fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		err = filc_require_head2_leaf(f_ctx, &fpr);
		if (err) {
			return err;
		}
		len = 0;
		err = fpr_write_to_leaf(&fpr, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_write_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_write_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_write_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

struct silofs_write_iter {
	struct silofs_rwiter_ctx rwi;
	const uint8_t *dat;
	size_t dat_len;
	size_t dat_max;
};

static struct silofs_write_iter *
write_iter_of(const struct silofs_rwiter_ctx *rwi)
{
	const struct silofs_write_iter *wri =
	        container_of2(rwi, struct silofs_write_iter, rwi);

	return unconst(wri);
}

static int write_iter_actor(struct silofs_rwiter_ctx *rwi,
                            const struct silofs_iovec *iov)
{
	struct silofs_write_iter *wri = write_iter_of(rwi);
	int err;

	if ((iov->iov_fd > 0) && (iov->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if ((wri->dat_len + iov->iov_len) > wri->dat_max) {
		return -SILOFS_EINVAL;
	}
	err = silofs_iovec_copy_from(iov, wri->dat + wri->dat_len);
	if (err) {
		return err;
	}
	wri->dat_len += iov->iov_len;
	return 0;
}

static int filc_write_iter(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (!err) {
		err = filc_write_data(f_ctx);
		filc_update_post_io(f_ctx, !err && (f_ctx->off > f_ctx->beg));
	}
	return err;
}

int silofs_do_write_iter(struct silofs_task *task,
                         struct silofs_inode_info *ii,
                         struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_WRITE,
		.with_backref = 1,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, rwi);

	filc_incref(&f_ctx);
	ret = filc_write_iter(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

int silofs_do_write(struct silofs_task *task, struct silofs_inode_info *ii,
                    const void *buf, size_t len, loff_t off, size_t *out_len)
{
	struct silofs_write_iter wri = {
		.rwi.actor = write_iter_actor,
		.rwi.len = len,
		.rwi.off = off,
		.dat = buf,
		.dat_len = 0,
		.dat_max = len
	};
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_WRITE,
		.with_backref = 0,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, &wri.rwi);
	filc_incref(&f_ctx);
	ret = filc_write_iter(&f_ctx);
	filc_decref(&f_ctx);
	*out_len = wri.dat_len;
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_do_rdwr_post(const struct silofs_task *task, int wr_mode,
                        const struct silofs_iovec *iov, size_t cnt)
{
	silofs_unused(task);
	for (size_t i = 0; i < cnt; ++i) {
		iovref_post(&iov[i], wr_mode);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_drop_remove_subtree(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *fni);

static int filc_discard_data_leaf(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	int err;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = filc_del_data_space(f_ctx, vaddr);
	if (err) {
		return err;
	}
	filc_update_iattr_blocks(f_ctx, vaddr, -1);
	return 0;
}

static int filc_drop_subtree(struct silofs_file_ctx *f_ctx,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = filc_stage_finode(f_ctx, vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_drop_remove_subtree(f_ctx, fni);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_drop_subtree_at(struct silofs_file_ctx *f_ctx,
                     const struct silofs_finode_info *parent_fni, size_t slot)
{
	struct silofs_vaddr vaddr;
	int err;

	fni_resolve_child_by_slot(parent_fni, slot, &vaddr);
	if (fni_isbottom(parent_fni)) {
		err = filc_discard_data_leaf(f_ctx, &vaddr);
	} else {
		err = filc_drop_subtree(f_ctx, &vaddr);
	}
	return err;
}

static int filc_drop_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni)
{
	const size_t nslots_max = ftn_nchilds_max(fni->ftn);
	int err = 0;

	fni_incref(fni);
	for (size_t slot = 0; (slot < nslots_max) && !err; ++slot) {
		err = filc_drop_subtree_at(f_ctx, fni, slot);
	}
	fni_decref(fni);
	return err;
}

static int filc_drop_finode(struct silofs_file_ctx *f_ctx,
                            struct silofs_finode_info *fni)
{
	int err = 0;

	ftn_dec_refcnt(fni->ftn);
	if (!ftn_refcnt(fni->ftn)) {
		err = filc_remove_finode(f_ctx, fni);
	}
	return err;
}

static int filc_drop_remove_subtree(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *fni)
{
	int err;

	err = filc_drop_recursive(f_ctx, fni);
	if (err) {
		return err;
	}
	err = filc_drop_finode(f_ctx, fni);
	if (err) {
		return err;
	}
	return 0;
}

static void filc_reset_tree_root(struct silofs_file_ctx *f_ctx)
{
	filc_set_tree_root_at(f_ctx, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static int filc_drop_tree_map(struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	err = filc_stage_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	err = filc_drop_remove_subtree(f_ctx, fni);
	if (err) {
		return err;
	}
	filc_reset_tree_root(f_ctx);
	return 0;
}

static int filc_drop_head1_leaf_at(struct silofs_file_ctx *f_ctx, size_t slot)
{
	struct silofs_vaddr vaddr;

	filc_head1_leaf_at(f_ctx, slot, &vaddr);
	return filc_discard_data_leaf(f_ctx, &vaddr);
}

static int filc_drop_head2_leaf_at(struct silofs_file_ctx *f_ctx, size_t slot)
{
	struct silofs_vaddr vaddr;

	filc_head2_leaf_at(f_ctx, slot, &vaddr);
	return filc_discard_data_leaf(f_ctx, &vaddr);
}

static void
filc_reset_head1_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot)
{
	filc_set_head1_leaf_at(f_ctx, slot, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static void
filc_reset_head2_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot)
{
	filc_set_head2_leaf_at(f_ctx, slot, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static size_t filc_num_head1_leaf_slots(const struct silofs_file_ctx *f_ctx)
{
	return ifl_num_head1_leaves(ii_ifl_of(f_ctx->ii));
}

static size_t filc_num_head2_leaf_slots(const struct silofs_file_ctx *f_ctx)
{
	return ifl_num_head2_leaves(ii_ifl_of(f_ctx->ii));
}

static int filc_drop_head_leaves(struct silofs_file_ctx *f_ctx)
{
	size_t nslots;
	int err;

	nslots = filc_num_head1_leaf_slots(f_ctx);
	for (size_t slot = 0; slot < nslots; ++slot) {
		err = filc_drop_head1_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		filc_reset_head1_leaf_at(f_ctx, slot);
	}
	nslots = filc_num_head2_leaf_slots(f_ctx);
	for (size_t slot = 0; slot < nslots; ++slot) {
		err = filc_drop_head2_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		filc_reset_head2_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int filc_drop_data_and_meta(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_drop_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_drop_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_drop_reg(struct silofs_task *task, struct silofs_inode_info *ii)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_drop_data_and_meta(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fpr_zero_data_leaf_range(struct silofs_fpos_ref *fpr)
{
	const struct silofs_vaddr *vaddr = &fpr->vaddr;
	const enum silofs_stype stype = vaddr->stype;
	const loff_t file_pos = fpr->file_pos;
	const loff_t off_in_bk = off_in_data(file_pos, stype);
	const size_t len = len_of_data(file_pos, fpr->f_ctx->end, stype);
	int err;

	fni_incref(fpr->fni);
	err = filc_zero_data_leaf_range(fpr->f_ctx, vaddr, off_in_bk, len);
	fni_decref(fpr->fni);
	return err;
}

static int fpr_discard_partial(struct silofs_fpos_ref *fpr)
{
	int err;

	err = fpr_unshare_leaf(fpr);
	if (err) {
		return err;
	}
	err = fpr_zero_data_leaf_range(fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int fpr_discard_data_leaf(const struct silofs_fpos_ref *fpr)
{
	int err;

	fni_incref(fpr->fni);
	err = filc_discard_data_leaf(fpr->f_ctx, &fpr->vaddr);
	fni_decref(fpr->fni);
	return err;
}

static int fpr_discard_entire(const struct silofs_fpos_ref *fpr)
{
	int err;

	err = fpr_discard_data_leaf(fpr);
	if (err) {
		return err;
	}
	if (fpr->head1) {
		filc_reset_head1_leaf_at(fpr->f_ctx, fpr->slot_idx);
	} else if (fpr->head2) {
		filc_reset_head2_leaf_at(fpr->f_ctx, fpr->slot_idx);
	} else if (fpr->tree && fpr->fni) { /* make clang-scan happy */
		fni_clear_subtree_mappings(fpr->fni, fpr->slot_idx);
		fni_difnify(fpr->fni, fpr->f_ctx->ii);
	}
	return 0;
}

static int fpr_discard_by_set_unwritten(const struct silofs_fpos_ref *fpr)
{
	return silofs_mark_unwritten_at(fpr->f_ctx->task, &fpr->vaddr);
}

static int fpr_discard_data_at(struct silofs_fpos_ref *fpr)
{
	int err;
	bool zero_range;

	if (!fpr->has_data) {
		return 0;
	}
	err = fpr_detect_shared(fpr);
	if (err) {
		return err;
	}
	if (fpr->partial) {
		return fpr_discard_partial(fpr);
	}
	zero_range = fl_mode_zero_range(fpr->f_ctx->fl_mode);
	if (zero_range && !fpr->shared) {
		return fpr_discard_by_set_unwritten(fpr);
	}
	return fpr_discard_entire(fpr);
}

static int filc_discard_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree_map(f_ctx, &fpr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = fpr_discard_data_at(&fpr);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_by_head_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, &fpr);
		err = fpr_discard_data_at(&fpr);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, &fpr);
		err = fpr_discard_data_at(&fpr);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_discard_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_discard_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_discard_unused_meta(struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->beg == 0) ? filc_drop_data_and_meta(f_ctx) : 0;
}

static loff_t filc_head_leaves_end(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_vaddr vaddr;
	size_t slot;

	slot = filc_num_head2_leaf_slots(f_ctx);
	while (slot-- > 0) {
		filc_head2_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			return off_head2_end_of(slot);
		}
	}
	slot = filc_num_head1_leaf_slots(f_ctx);
	while (slot-- > 0) {
		filc_head1_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			return off_head1_end_of(slot);
		}
	}
	return 0;
}

static int
filc_resolve_tree_end(const struct silofs_file_ctx *f_ctx, loff_t *out_end)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	*out_end = 0;
	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	err = filc_stage_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	*out_end = ftn_end(fni->ftn);
	return 0;
}

static int filc_resolve_truncate_end(struct silofs_file_ctx *f_ctx)
{
	loff_t tend;
	loff_t lend;
	int err;

	err = filc_resolve_tree_end(f_ctx, &tend);
	if (err) {
		return err;
	}
	lend = filc_head_leaves_end(f_ctx);
	f_ctx->end = off_max3(f_ctx->off, lend, tend);
	return 0;
}

static int filc_truncate(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = filc_resolve_truncate_end(f_ctx);
	if (err) {
		return err;
	}
	err = filc_discard_data(f_ctx);
	if (err) {
		return err;
	}
	err = filc_discard_unused_meta(f_ctx);
	if (err) {
		return err;
	}
	filc_update_post_io(f_ctx, err == 0);
	return 0;
}

int silofs_do_truncate(struct silofs_task *task,
                       struct silofs_inode_info *ii, loff_t off)
{
	const loff_t isp = ii_span(ii);
	const size_t len = (off < isp) ? off_ulen(off, isp) : 0;
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.len = len,
		.beg = off,
		.off = off,
		.end = off_end(off, len),
		.op_mask = OP_TRUNC,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_truncate(&f_ctx);
	filc_decref(&f_ctx);

	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_lseek_data_leaf(struct silofs_file_ctx *f_ctx,
                                struct silofs_fpos_ref *fpr)
{
	int err;

	err = filc_seek_data_by_head_leaves(f_ctx, fpr);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = filc_seek_by_tree_map(f_ctx, fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_lseek_data(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	loff_t isz;
	int err;

	isz = ii_size(f_ctx->ii);
	err = filc_lseek_data_leaf(f_ctx, &fpr);
	if (err == -SILOFS_ENOENT) {
		f_ctx->off = isz;
		return -SILOFS_ENXIO;
	}
	if (err) {
		return err;
	}
	f_ctx->off = off_clamp(fpr.file_pos, f_ctx->off, isz);
	return 0;
}

static int filc_lseek_hole_noleaf(struct silofs_file_ctx *f_ctx,
                                  struct silofs_fpos_ref *fpr)
{
	int err;

	err = filc_seek_hole_by_head_leaves(f_ctx, fpr);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = filc_seek_by_tree_map(f_ctx, fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_lseek_hole(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr = { .file_pos = -1 };
	loff_t isz;
	int err;

	isz = ii_size(f_ctx->ii);
	err = filc_lseek_hole_noleaf(f_ctx, &fpr);
	if (err == 0) {
		f_ctx->off = off_clamp(fpr.file_pos, f_ctx->off, isz);
	} else if (err == -SILOFS_ENOENT) {
		f_ctx->off = isz;
		err = 0;
	}
	return err;
}

static int filc_lseek_notsupp(struct silofs_file_ctx *f_ctx)
{
	f_ctx->off = f_ctx->end;
	return -SILOFS_EOPNOTSUPP;
}

static int filc_lseek(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (err) {
		return err;
	}
	if (filc_is_seek_data(f_ctx)) {
		return filc_lseek_data(f_ctx);
	}
	if (filc_is_seek_hole(f_ctx)) {
		return filc_lseek_hole(f_ctx);
	}
	return filc_lseek_notsupp(f_ctx);
}

int silofs_do_lseek(struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    loff_t off, int whence, loff_t *out_off)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.len = 0,
		.beg = off,
		.off = off,
		.end = ii_size(ii),
		.op_mask = OP_LSEEK,
		.whence = whence,
		.stg_mode = SILOFS_STG_CUR,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_lseek(&f_ctx);
	filc_decref(&f_ctx);

	*out_off = f_ctx.off;
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0012: Proper hanfling for FALLOC_FL_KEEP_SIZE beyond file size
 *
 * See 'man 2 fallocate' for semantics details of FALLOC_FL_KEEP_SIZE
 * beyond end-of-file.
 */
static int filc_check_fl_mode(const struct silofs_file_ctx *f_ctx)
{
	int mask;
	const int mode = f_ctx->fl_mode;

	/* punch hole and zero range are mutually exclusive */
	mask = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;
	if ((mode & mask) == mask) {
		return -SILOFS_EOPNOTSUPP;
	}
	/* currently supported modes */
	mask = FALLOC_FL_KEEP_SIZE |
	       FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;
	if (mode & ~mask) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int filc_create_bind_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni)
{
	struct silofs_fpos_ref fpr;
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fni, &fpr);
	if (fpr.has_data) {
		return fpr_require_mutable(&fpr);
	}
	err = filc_create_data_leaf(f_ctx, SILOFS_STYPE_DATABK, &fpr.vaddr);
	if (err) {
		return err;
	}
	fni_bind_child(parent_fni, f_ctx->off, &fpr.vaddr);
	fni_difnify(parent_fni, f_ctx->ii);
	return 0;
}

static int filc_reserve_tree_leaves(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni)
{
	int ret = 0;
	bool next_mapping = false;

	fni_incref(parent_fni);
	while (filc_has_more_io(f_ctx) && !next_mapping) {
		ret = filc_create_bind_tree_leaf(f_ctx, parent_fni);
		if (ret) {
			break;
		}
		filc_advance_to_next(f_ctx);
		next_mapping = filc_ismapping_boundaries(f_ctx);
	}
	fni_decref(parent_fni);
	return ret;
}

static int filc_reserve_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *fni = NULL;
	size_t height;
	int err;

	err = filc_stage_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	height = fni_height(fni);
	for (size_t level = height; level > 0; --level) {
		if (fni_isbottom(fni)) {
			return filc_reserve_tree_leaves(f_ctx, fni);
		}
		err = filc_require_finode(f_ctx, fni, &fni);
		if (err) {
			return err;
		}
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_reserve_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_create_tree_spine(f_ctx);
	if (err) {
		return err;
	}
	err = filc_reserve_leaves(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_fallocate_reserve_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	int err = 0;

	while (!err && filc_has_more_io(f_ctx)) {
		err = filc_reserve_by_tree_map(f_ctx);
	}
	return err;
}

static int filc_fallocate_reserve_by_head_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		err = filc_require_head1_leaf(f_ctx, &fpr);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		err = filc_require_head2_leaf(f_ctx, &fpr);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_fallocate_reserve(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_fallocate_reserve_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_fallocate_reserve_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_fallocate_punch_hole(struct silofs_file_ctx *f_ctx)
{
	return filc_discard_data(f_ctx);
}

static int filc_fallocate_zero_range(struct silofs_file_ctx *f_ctx)
{
	return filc_discard_data(f_ctx);
}

static int filc_fallocate_op(struct silofs_file_ctx *f_ctx)
{
	const int fl_mode = f_ctx->fl_mode;
	int err;

	if (fl_mode_reserve_range(fl_mode)) {
		err = filc_fallocate_reserve(f_ctx);
	} else if (fl_mode_punch_hole(fl_mode)) {
		err = filc_fallocate_punch_hole(f_ctx);
	} else if (fl_mode_zero_range(fl_mode)) {
		err = filc_fallocate_zero_range(f_ctx);
	} else {
		err = -SILOFS_EOPNOTSUPP;
	}
	return err;
}

static int filc_fallocate(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = filc_check_fl_mode(f_ctx);
	if (err) {
		return err;
	}
	err = filc_fallocate_op(f_ctx);
	if (err) {
		return err;
	}
	filc_update_post_io(f_ctx, false);
	return 0;
}

int silofs_do_fallocate(struct silofs_task *task,
                        struct silofs_inode_info *ii,
                        int mode, loff_t off, loff_t len)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.len = (size_t)len,
		.beg = off,
		.off = off,
		.end = off_end(off, (size_t)len),
		.op_mask = OP_FALLOC,
		.fl_mode = mode,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_fallocate(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool filc_emit_fiemap_ext(struct silofs_file_ctx *f_ctx,
                                 const struct silofs_vaddr *vaddr)
{
	loff_t end;
	size_t len;
	struct fiemap_extent *fm_ext;
	struct fiemap *fm = f_ctx->fm;

	end = off_min(off_end(f_ctx->off, vaddr->len), f_ctx->end);
	len = len_of_data(f_ctx->off, end, vaddr->stype);
	if (len == 0) {
		return false;
	}
	if (fm->fm_extent_count == 0) {
		fm->fm_mapped_extents++;
		return true;
	}
	if (fm->fm_mapped_extents >= fm->fm_extent_count) {
		return false;
	}
	fm_ext = &fm->fm_extents[fm->fm_mapped_extents++];
	fm_ext->fe_flags = FIEMAP_EXTENT_DATA_ENCRYPTED;
	fm_ext->fe_logical = (uint64_t)(f_ctx->off);
	fm_ext->fe_physical = (uint64_t)(vaddr->off);
	fm_ext->fe_length = len;
	return true;
}

static bool filc_emit_fiemap(struct silofs_file_ctx *f_ctx,
                             const struct silofs_fpos_ref *fpr)
{
	bool ok = true;

	if (fpr->has_data) {
		ok = filc_emit_fiemap_ext(f_ctx, &fpr->vaddr);
		if (!ok) {
			f_ctx->fm_stop = true;
		}
	}
	return ok;
}

static int filc_fiemap_by_tree_leaves(struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni)
{
	struct silofs_fpos_ref fpr;

	fni_incref(parent_fni);
	while (filc_has_more_io(f_ctx)) {
		filc_resolve_tree_leaf(f_ctx, parent_fni, &fpr);
		if (!filc_emit_fiemap(f_ctx, &fpr)) {
			break;
		}
		filc_advance_to_next(f_ctx);
		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	fni_decref(parent_fni);
	return 0;
}

static int filc_fiemap_by_tree_map(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fpr;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree_map(f_ctx, &fpr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = filc_fiemap_by_tree_leaves(f_ctx, fpr.fni);
		if (err) {
			return err;
		}
		/* TODO: need to skip large holes */
	}
	return 0;
}

static int filc_fiemap_by_head_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fpos_ref fm;

	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, &fm);
		if (!filc_emit_fiemap(f_ctx, &fm)) {
			break;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, &fm);
		if (!filc_emit_fiemap(f_ctx, &fm)) {
			break;
		}
		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_fiemap_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_fiemap_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = filc_fiemap_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_check_fm_flags(const struct silofs_file_ctx *f_ctx)
{
	const int fm_allowed =
	        FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR | FIEMAP_FLAG_CACHE;

	if (f_ctx->fm_flags & ~fm_allowed) {
		return -SILOFS_EOPNOTSUPP;
	}
	if (f_ctx->fm_flags & fm_allowed) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int filc_fiemap(struct silofs_file_ctx *f_ctx)
{
	int ret;

	f_ctx->fm->fm_mapped_extents = 0;
	ret = filc_check_file_io(f_ctx);
	if (ret) {
		return ret;
	}
	ret = filc_check_fm_flags(f_ctx);
	if (ret) {
		return ret;
	}
	ret = filc_fiemap_data(f_ctx);
	if (ret) {
		return ret;
	}
	return 0;
}

static loff_t ii_off_end(const struct silofs_inode_info *ii,
                         loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t isz = ii_size(ii);

	return off_min(end, isz);
}

int silofs_do_fiemap(struct silofs_task *task,
                     struct silofs_inode_info *ii, struct fiemap *fm)
{
	const loff_t off = (loff_t)fm->fm_start;
	const size_t len = (size_t)fm->fm_length;
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii,
		.len = len,
		.beg = off,
		.off = off,
		.end = ii_off_end(ii, off, len),
		.op_mask = OP_FIEMAP,
		.fm = fm,
		.fm_flags = (int)(fm->fm_flags),
		.fm_stop = 0,
		.whence = SEEK_DATA,
		.stg_mode = SILOFS_STG_CUR,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_fiemap(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                            struct silofs_finode_info *parent_fni,
                            struct silofs_fpos_ref *out_fpr);

static int
filc_resolve_fpos_by_head_leaves(struct silofs_file_ctx *f_ctx,
                                 struct silofs_fpos_ref *out_fpr)
{
	int err = 0;

	if (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fpr);
	} else if (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fpr);
	} else {
		fpr_none(out_fpr, f_ctx, NULL, f_ctx->off);
		err = -SILOFS_ENOENT;
	}
	return err;
}

static int
filc_resolve_fpos_recursive_at(struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni,
                               size_t slot,  struct silofs_fpos_ref *out_fpr)
{
	struct silofs_vaddr vaddr;
	struct silofs_finode_info *fni = NULL;
	int err;

	fni_resolve_child_by_slot(parent_fni, slot, &vaddr);
	fpr_none(out_fpr, f_ctx, parent_fni, f_ctx->off);

	if (vaddr_isnull(&vaddr)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_finode(f_ctx, &vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_resolve_fpos_recursive(f_ctx, fni, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_do_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni,
                               struct silofs_fpos_ref *out_fpr)
{
	size_t slot;

	if (!fni_isinrange(parent_fni, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}
	slot = fni_child_slot_of(parent_fni, f_ctx->off);
	if (!fni_isbottom(parent_fni)) {
		return filc_resolve_fpos_recursive_at(f_ctx, parent_fni,
		                                      slot, out_fpr);
	}
	filc_resolve_child_at(f_ctx, parent_fni, f_ctx->off, slot, out_fpr);
	return 0;
}


static int filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_finode_info *parent_fni,
                                       struct silofs_fpos_ref *out_fpr)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_resolve_fpos_recursive(f_ctx, parent_fni, out_fpr);
	fni_decref(parent_fni);
	return ret;
}

static int filc_resolve_fpos_by_tree_map(struct silofs_file_ctx *f_ctx,
                struct silofs_fpos_ref *out_fpr)
{
	struct silofs_finode_info *root_fni = NULL;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_root(f_ctx, &root_fni);
	if (err) {
		return err;
	}
	err = filc_resolve_fpos_recursive(f_ctx, root_fni, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_resolve_fpos(struct silofs_file_ctx *f_ctx,
                             struct silofs_fpos_ref *out_fpr)
{
	int err;

	err = filc_resolve_fpos_by_head_leaves(f_ctx, out_fpr);
	if (err == -SILOFS_ENOENT) {
		err = filc_resolve_fpos_by_tree_map(f_ctx, out_fpr);
	}
	return err;
}

static size_t filc_copy_length_of(const struct silofs_file_ctx *f_ctx)
{
	const size_t len_to_end = off_ulen(f_ctx->off, f_ctx->end);
	const size_t len_to_next = filc_distance_to_next(f_ctx);

	return min(len_to_end, len_to_next);
}

static size_t fpr_copy_range_length(const struct silofs_fpos_ref *fpr_src,
                                    const struct silofs_fpos_ref *fpr_dst)
{
	const size_t len_src = filc_copy_length_of(fpr_src->f_ctx);
	const size_t len_dst = filc_copy_length_of(fpr_dst->f_ctx);

	return min(len_src, len_dst);
}


static int fpr_clear_unwritten_of(struct silofs_fpos_ref *fpr,
                                  struct silofs_fileaf_info *fli)
{
	int err;

	if (fpr->unwritten) {
		err = filc_clear_unwritten_of(fpr->f_ctx, fli);
		if (err) {
			return err;
		}
		fpr->unwritten = false;
	}
	return 0;
}

static int
fpr_copy_data_leaf(struct silofs_fpos_ref *fpr_src,
                   struct silofs_fpos_ref *fpr_dst, size_t len)
{
	struct silofs_iovec iov_src = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_iovec iov_dst = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_fileaf_info *fli_src = NULL;
	struct silofs_fileaf_info *fli_dst = NULL;
	int err;
	bool all;

	err = filc_stage_fileaf(fpr_src->f_ctx, &fpr_src->vaddr, &fli_src);
	if (err) {
		goto out;
	}
	fli_incref(fli_src);

	err = filc_stage_fileaf(fpr_dst->f_ctx, &fpr_dst->vaddr, &fli_dst);
	if (err) {
		goto out;
	}
	fli_incref(fli_dst);

	all = (len == fpr_src->vaddr.len);
	err = filc_iovec_by_fileaf(fpr_src->f_ctx, fli_src, all, &iov_src);
	if (err) {
		goto out;
	}

	all = (len == fpr_dst->vaddr.len);
	err = filc_iovec_by_fileaf(fpr_dst->f_ctx, fli_dst, all, &iov_dst);
	if (err) {
		goto out;
	}

	err = silofs_iovec_copy_mem(&iov_src, &iov_dst, len);
	if (err) {
		goto out;
	}
	fli_dirtify(fli_dst, fpr_dst->f_ctx->ii);

	err = fpr_clear_unwritten_of(fpr_dst, fli_dst);
	if (err) {
		goto out;
	}
out:
	fli_decref(fli_dst);
	fli_decref(fli_src);
	return err;
}

static int fpr_copy_leaf(struct silofs_fpos_ref *fpr_src,
                         struct silofs_fpos_ref *fpr_dst, size_t len)
{
	int err;

	err = filc_pre_write_leaf(fpr_dst->f_ctx, fpr_dst, len);
	if (err) {
		return err;
	}
	err = filc_pre_write_leaf(fpr_src->f_ctx, fpr_src, len);
	if (err) {
		return err;
	}
	err = fpr_copy_data_leaf(fpr_src, fpr_dst, len);
	if (err) {
		return err;
	}
	return 0;
}

static void fpr_rebind_child(struct silofs_fpos_ref *fpr,
                             const struct silofs_vaddr *vaddr)
{
	fni_bind_child(fpr->fni, fpr->f_ctx->off, vaddr);
	fni_difnify(fpr->fni, fpr->f_ctx->ii);
	vaddr_assign(&fpr->vaddr, vaddr);
}

static int fpr_unshare_leaf(struct silofs_fpos_ref *fpr)
{
	struct silofs_fpos_ref fpr_new;
	const struct silofs_file_ctx *f_ctx = fpr->f_ctx;
	int err;

	silofs_assert(fpr->has_data);
	if (!fpr->shared || !fpr->tree) {
		return 0;
	}
	fpr_setup(&fpr_new, f_ctx, fpr->fni, &fpr->vaddr, fpr->file_pos);
	err = filc_claim_data_space(f_ctx, fpr->vaddr.stype, &fpr_new.vaddr);
	if (err) {
		return err;
	}
	err = fpr_copy_data_leaf(fpr, &fpr_new, fpr->vaddr.len);
	if (err) {
		filc_reclaim_data_space(f_ctx, &fpr_new.vaddr);
		return err;
	}
	err = filc_reclaim_data_space(f_ctx, &fpr->vaddr);
	if (err) {
		return err;
	}
	fpr_rebind_child(fpr, &fpr_new.vaddr);
	return 0;
}

static int filc_require_tree_leaf2(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fpos_ref *out_fpr)
{
	struct silofs_finode_info *parent_fni = NULL;
	int err;

	err = filc_require_tree(f_ctx, &parent_fni);
	if (err) {
		return err;
	}
	err = filc_require_tree_leaf(f_ctx, parent_fni, out_fpr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_require_leaf(const struct silofs_file_ctx *f_ctx,
                             struct silofs_fpos_ref *out_fpr)
{
	int err;

	if (off_is_head1(f_ctx->off)) {
		err = filc_require_head1_leaf(f_ctx, out_fpr);
	} else if (off_is_head2(f_ctx->off)) {
		err = filc_require_head2_leaf(f_ctx, out_fpr);
	} else {
		err = filc_require_tree_leaf2(f_ctx, out_fpr);
	}
	return err;
}

static int fpr_require_leaf(struct silofs_fpos_ref *fpr)
{
	return filc_require_leaf(fpr->f_ctx, fpr);
}

static int fpr_require_tree(struct silofs_fpos_ref *fpr)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	err = filc_require_tree(fpr->f_ctx, &fni);
	if (err) {
		return err;
	}
	filc_resolve_tree_leaf(fpr->f_ctx, fni, fpr);
	return 0;
}

static int fpr_share_leaf(const struct silofs_fpos_ref *fpr_src,
                          struct silofs_fpos_ref *fpr_dst)
{
	int err;

	err = filc_share_data_space(fpr_src->f_ctx, &fpr_src->vaddr);
	if (err) {
		return err;
	}
	fpr_rebind_child(fpr_dst, &fpr_src->vaddr);
	filc_update_iattr_blocks(fpr_dst->f_ctx, &fpr_dst->vaddr, 1);
	return 0;
}

static bool fpr_ismutable(const struct silofs_fpos_ref *fpr)
{
	return oaddr_isnull(&fpr->oaddr) ||
	       silofs_sbi_ismutable_oaddr(fpr->f_ctx->sbi, &fpr->oaddr);
}

static bool fpr_may_share_leaf(const struct silofs_fpos_ref *fpr_src,
                               const struct silofs_fpos_ref *fpr_dst)
{
	return (fpr_src->has_data && fpr_src->tree && !fpr_src->partial &&
	        fpr_dst->tree && !fpr_dst->partial &&
	        fpr_ismutable(fpr_src) && fpr_ismutable(fpr_dst));
}

static int
fpr_copy_range_at_leaf(struct silofs_fpos_ref *fpr_src,
                       struct silofs_fpos_ref *fpr_dst, size_t len)
{
	int err;

	if (!fpr_src->has_data && fpr_dst->has_data) {
		err = fpr_require_mutable(fpr_dst);
		if (err) {
			return err;
		}
		err = fpr_unshare_leaf(fpr_dst);
		if (err) {
			return err;
		}
		err = fpr_discard_data_at(fpr_dst);
		if (err) {
			return err;
		}
	} else if (fpr_src->has_data && !fpr_dst->has_data) {
		err = fpr_resolve_oaddr(fpr_src);
		if (err) {
			return err;
		}
		if (fpr_may_share_leaf(fpr_src, fpr_dst)) {
			err = fpr_require_tree(fpr_dst);
			if (err) {
				return err;
			}
			err = fpr_share_leaf(fpr_src, fpr_dst);
			if (err) {
				return err;
			}
		} else {
			err = fpr_require_leaf(fpr_dst);
			if (err) {
				return err;
			}
			err = fpr_require_mutable(fpr_dst);
			if (err) {
				return err;
			}
			err = fpr_copy_leaf(fpr_src, fpr_dst, len);
			if (err) {
				return err;
			}
		}
	} else if (fpr_src->has_data && fpr_dst->has_data) {
		err = fpr_require_mutable(fpr_dst);
		if (err) {
			return err;
		}
		err = fpr_resolve_oaddr(fpr_src);
		if (err) {
			return err;
		}
		err = fpr_resolve_oaddr(fpr_dst);
		if (err) {
			return err;
		}
		if (fpr_may_share_leaf(fpr_src, fpr_dst)) {
			err = fpr_discard_data_at(fpr_dst);
			if (err) {
				return err;
			}
			err = fpr_share_leaf(fpr_src, fpr_dst);
			if (err) {
				return err;
			}
		} else {
			err = fpr_copy_leaf(fpr_src, fpr_dst, len);
			if (err) {
				return err;
			}
		}
	}  /* else: !fpr_src->has_data && !fpr_dst->has_data (no-op) */
	return 0;
}

static int filc_copy_range_iter(struct silofs_file_ctx *f_ctx_src,
                                struct silofs_file_ctx *f_ctx_dst)
{
	struct silofs_fpos_ref fpr_src;
	struct silofs_fpos_ref fpr_dst;
	size_t len;
	int err;

	while (filc_has_more_io(f_ctx_src) && filc_has_more_io(f_ctx_dst)) {
		err = filc_resolve_fpos(f_ctx_src, &fpr_src);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		err = filc_resolve_fpos(f_ctx_dst, &fpr_dst);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		len = fpr_copy_range_length(&fpr_src, &fpr_dst);
		if (!len) {
			break;
		}
		err = fpr_copy_range_at_leaf(&fpr_src, &fpr_dst, len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx_src, len);
		filc_advance_by_nbytes(f_ctx_dst, len);

		fpr_reset(&fpr_src);
		fpr_reset(&fpr_dst);
	}
	return 0;
}

static int filc_check_copy_range(const struct silofs_file_ctx *f_ctx_src,
                                 const struct silofs_file_ctx *f_ctx_dst)
{
	const long len = (long)(f_ctx_dst->len);
	const loff_t off_src = f_ctx_src->off;
	const loff_t off_dst = f_ctx_dst->off;
	int err;

	err = filc_check_file_io(f_ctx_src);
	if (err) {
		return err;
	}
	err = filc_check_file_io(f_ctx_dst);
	if (err) {
		return err;
	}
	/* don't allow overlapped copying within the same file. */
	if ((f_ctx_src->ii == f_ctx_dst->ii) &&
	    ((off_dst + len) > off_src) && (off_dst < (off_src + len))) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int filc_flush_dirty_now(struct silofs_file_ctx *f_ctx)
{
	return silofs_flush_dirty(f_ctx->task, f_ctx->ii, SILOFS_F_NOW);
}

static int filc_pre_copy_range(struct silofs_file_ctx *f_ctx_src,
                               struct silofs_file_ctx *f_ctx_dst)
{
	int err;

	err = filc_flush_dirty_now(f_ctx_src);
	if (err) {
		return err;
	}
	err = filc_flush_dirty_now(f_ctx_dst);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_do_copy_range(struct silofs_file_ctx *f_ctx_src,
                   struct silofs_file_ctx *f_ctx_dst, size_t *out_ncp)
{
	int err;

	err = filc_check_copy_range(f_ctx_src, f_ctx_dst);
	if (err) {
		return err;
	}
	err = filc_pre_copy_range(f_ctx_src, f_ctx_dst);
	if (err) {
		return err;
	}
	err = filc_copy_range_iter(f_ctx_src, f_ctx_dst);
	if (err) {
		return err;
	}
	filc_update_post_io(f_ctx_dst, false);
	*out_ncp = filc_io_length(f_ctx_dst);
	return 0;
}

static int filc_copy_range(struct silofs_file_ctx *f_ctx_src,
                           struct silofs_file_ctx *f_ctx_dst, size_t *out_ncp)
{
	int ret;

	filc_incref(f_ctx_src);
	filc_incref(f_ctx_dst);
	ret = filc_do_copy_range(f_ctx_src, f_ctx_dst, out_ncp);
	filc_decref(f_ctx_dst);
	filc_decref(f_ctx_src);
	return ret;
}

int silofs_do_copy_file_range(struct silofs_task *task,
                              struct silofs_inode_info *ii_in,
                              struct silofs_inode_info *ii_out,
                              loff_t off_in, loff_t off_out, size_t len,
                              int flags, size_t *out_ncp)
{
	struct silofs_file_ctx f_ctx_src = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii_in,
		.len = len,
		.beg = off_in,
		.off = off_in,
		.end = ii_off_end(ii_in, off_in, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
		.with_backref = 0,
		.stg_mode = SILOFS_STG_CUR,
	};
	struct silofs_file_ctx f_ctx_dst = {
		.task = task,
		.uber = task->t_uber,
		.sbi = task_sbi(task),
		.ii = ii_out,
		.len = len,
		.beg = off_out,
		.off = off_out,
		.end = ii_off_end(ii_out, off_out, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
		.with_backref = 0,
		.stg_mode = SILOFS_STG_COW,
	};

	return filc_copy_range(&f_ctx_src, &f_ctx_dst, out_ncp);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_setup_reg(struct silofs_inode_info *ii)
{
	struct silofs_inode_file *ifl = ii_ifl_of(ii);

	ifl_setup(ifl);
	ii_dirtify(ii);
}

int silofs_verify_ftree_node(const struct silofs_ftree_node *ftn)
{
	loff_t spbh;
	const loff_t span = ftn_span(ftn);
	const size_t height = ftn_height(ftn);
	enum silofs_stype child_stype;
	enum silofs_stype expect_stype;
	int err;

	err = silofs_verify_ino(ftn_ino(ftn));
	if (err) {
		return err;
	}
	if ((ftn_beg(ftn) < 0) || (ftn_end(ftn) < 0)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (ftn_beg(ftn) >= ftn_end(ftn)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height <= 1) || (height > 7)) {
		return -SILOFS_EFSCORRUPTED;
	}
	spbh = ftn_span_by_height(ftn, height);
	if (span != spbh) {
		return -SILOFS_EFSCORRUPTED;
	}
	child_stype = ftn_child_stype(ftn);
	ftn_child_stype_by_height(ftn, height, &expect_stype);
	if (!stype_isequal(child_stype, expect_stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (ftn_isbottom(ftn) && !stype_isdatabk(child_stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}
