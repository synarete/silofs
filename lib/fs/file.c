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
#include <linux/falloc.h>
#include <linux/fiemap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define OP_READ       (1 << 0)
#define OP_WRITE      (1 << 1)
#define OP_TRUNC      (1 << 2)
#define OP_FALLOC     (1 << 3)
#define OP_FIEMAP     (1 << 4)
#define OP_LSEEK      (1 << 5)
#define OP_COPY_RANGE (1 << 6)

struct silofs_file_ctx {
	struct silofs_task *task;
	struct silofs_fsenv *fsenv;
	struct silofs_sb_info *sbi;
	struct silofs_inode_info *ii;
	struct silofs_rwiter_ctx *rwi_ctx;
	struct fiemap *fm;
	size_t len;
	loff_t beg;
	loff_t off;
	loff_t end;
	int op_mask;
	int fl_mode;
	int fm_flags;
	int fm_stop;
	int cp_flags;
	int whence;
	int with_backref;
	int o_flags;
	enum silofs_stg_mode stg_mode;
};

struct silofs_fileaf_ref {
	struct silofs_laddr laddr;
	struct silofs_vaddr vaddr;
	const struct silofs_inode_info *ii;
	struct silofs_finode_info *parent_fni;
	loff_t file_pos;
	size_t slot_idx;
	size_t leaf_size;
	bool head1;
	bool head2;
	bool tree;
	bool partial;
	bool shared;
	bool has_data;
	bool has_hole;
	bool unwritten;
};

/* local functions forward declarations */
static int filc_unshare_leaf_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_fileaf_ref *flref);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static enum silofs_file_type ii_ftype(const struct silofs_inode_info *ii)
{
	const enum silofs_inodef iflags = ii_flags(ii);
	enum silofs_file_type ftype = SILOFS_FILE_TYPE_NONE;

	if (ii_isreg(ii)) {
		if (iflags & SILOFS_INODEF_FTYPE2) {
			ftype = SILOFS_FILE_TYPE2;
		} else {
			ftype = SILOFS_FILE_TYPE1;
		}
	}
	return ftype;
}

static bool ii_isftype1(const struct silofs_inode_info *ii)
{
	return (ii_ftype(ii) == SILOFS_FILE_TYPE1);
}

static bool ii_isftype2(const struct silofs_inode_info *ii)
{
	return (ii_ftype(ii) == SILOFS_FILE_TYPE2);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static loff_t off_max3(loff_t off1, loff_t off2, loff_t off3)
{
	return off_max(off_max(off1, off2), off3);
}

static loff_t off_clamp(loff_t off1, loff_t off2, loff_t off3)
{
	return off_min(off_max(off1, off2), off3);
}

static bool off_is_within(loff_t off, loff_t beg, loff_t end)
{
	return (beg <= off) && (off < end);
}

static bool off_is_lbk_aligned(loff_t off)
{
	return (off % SILOFS_LBK_SIZE) == 0;
}

static loff_t off_in_data(loff_t off, enum silofs_ltype ltype)
{
	const ssize_t len = ltype_ssize(ltype);

	return off % len;
}

static size_t len_to_next(loff_t off, enum silofs_ltype ltype)
{
	const ssize_t len = ltype_ssize(ltype);
	const loff_t next = off_next(off, len);

	return off_ulen(off, next);
}

static size_t len_of_data(loff_t off, loff_t end, enum silofs_ltype ltype)
{
	const ssize_t len = ltype_ssize(ltype);
	const loff_t next = off_next(off, len);

	return (next < end) ? off_ulen(off, next) : off_ulen(off, end);
}

static bool off_is_partial(loff_t off, loff_t end, enum silofs_ltype ltype)
{
	const ssize_t data_len = ltype_ssize(ltype);
	const loff_t off_start = off_align(off, data_len);
	const ssize_t io_len = off_len(off, end);

	return (off != off_start) || (io_len < data_len);
}

static bool off_is_partial_head1(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATA1K);
}

static bool off_is_partial_head2(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATA4K);
}

static bool off_is_partial_leaf(loff_t off, loff_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATABK);
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
	return off_is_within(off, 0, off_head1_max());
}

static bool off_is_head2(loff_t off)
{
	return off_is_within(off, off_head1_max(), off_head2_max());
}

static size_t off_to_head1_slot(loff_t off)
{
	const size_t slot_size = SILOFS_FILE_HEAD1_LEAF_SIZE;
	size_t slot;

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

static size_t off_to_leaf_slot(loff_t off)
{
	const size_t slot_size = SILOFS_FILE_TREE_LEAF_SIZE;
	const size_t nchilds = SILOFS_FILE_NODE_NCHILDS;

	return ((size_t)off / slot_size) % nchilds;
}

static size_t off_to_tree_height(loff_t off)
{
	const long leaf_size = SILOFS_FILE_TREE_LEAF_SIZE;
	const int shift = SILOFS_FILE_MAP_SHIFT;
	size_t height = 2;
	loff_t xpos;

	/* TODO: count bits */
	if (off > leaf_size) {
		xpos = (off / leaf_size) >> shift;
		while (xpos > 0) {
			height += 1;
			xpos = (xpos >> shift);
		}
	}
	return height;
}

static bool ft_height_isbottom(size_t height)
{
	silofs_expect_ge(height, 1);
	silofs_expect_le(height, SILOFS_FILE_HEIGHT_MAX);

	return (height <= 2);
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

static void
fli_dirtify(struct silofs_fileaf_info *fli, struct silofs_inode_info *ii)
{
	vni_dirtify(&fli->fl_vni, ii);
}

static void fli_incref(struct silofs_fileaf_info *fli)
{
	if (likely(fli != NULL)) {
		vni_incref(&fli->fl_vni);
	}
}

static void fli_decref(struct silofs_fileaf_info *fli)
{
	if (likely(fli != NULL)) {
		vni_decref(&fli->fl_vni);
	}
}

static const struct silofs_vaddr *
fli_vaddr(const struct silofs_fileaf_info *fli)
{
	return (fli != NULL) ? vni_vaddr(&fli->fl_vni) : NULL;
}

static enum silofs_ltype fli_ltype(const struct silofs_fileaf_info *fli)
{
	return vni_ltype(&fli->fl_vni);
}

static size_t fli_data_len(const struct silofs_fileaf_info *fli)
{
	return ltype_size(fli_ltype(fli));
}

static void *fli_data_at(const struct silofs_fileaf_info *fli, loff_t pos)
{
	size_t dat_size = 0;
	uint8_t *dat_base = NULL;
	const enum silofs_ltype ltype = fli_ltype(fli);

	if (silofs_ltype_isdata1k(ltype)) {
		dat_size = sizeof(fli->flu.db1->dat);
		dat_base = fli->flu.db1->dat;
	} else if (silofs_ltype_isdata4k(ltype)) {
		dat_size = sizeof(fli->flu.db4->dat);
		dat_base = fli->flu.db4->dat;
	} else if (silofs_ltype_isdatabk(ltype)) {
		dat_size = sizeof(fli->flu.db->dat);
		dat_base = fli->flu.db->dat;
	}

	if ((dat_base == NULL) || (pos >= (ssize_t)dat_size) || (pos < 0)) {
		silofs_panic("illegal reference for file-data: "
		             "ltype=%d pos=%ld",
		             (int)ltype, pos);
	}
	return &dat_base[pos];
}

static loff_t fli_off_within(const struct silofs_fileaf_info *fli, loff_t off)
{
	return off_in_data(off, fli_ltype(fli));
}

static size_t
fli_len_within(const struct silofs_fileaf_info *fli, loff_t off, loff_t end)
{
	return len_of_data(off, end, fli_ltype(fli));
}

static bool fli_asyncwr(const struct silofs_fileaf_info *fli)
{
	const struct silofs_fsenv *fsenv = vni_fsenv(&fli->fl_vni);

	return (fsenv->fse_ctl_flags & SILOFS_ENVF_ASYNCWR) > 0;
}

static void fli_pre_io(struct silofs_fileaf_info *fli, int wr_mode)
{
	fli_incref(fli);
	if (wr_mode && fli_asyncwr(fli)) {
		silofs_atomic_add(&fli->fl_vni.vn_asyncwr, 1);
	}
}

static void fli_post_io(struct silofs_fileaf_info *fli, int wr_mode)
{
	fli_decref(fli);
	if (wr_mode && fli_asyncwr(fli)) {
		silofs_atomic_sub(&fli->fl_vni.vn_asyncwr, 1);
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
	return ft_height_isbottom(ftn_height(ftn));
}

static size_t ftn_nbytes_per_slot(const struct silofs_ftree_node *ftn)
{
	return (size_t)ftn_span(ftn) / ftn_nchilds_max(ftn);
}

static size_t
ftn_slot_by_file_pos(const struct silofs_ftree_node *ftn, loff_t file_pos)
{
	const size_t nslots = ftn_nchilds_max(ftn);
	const int shift = SILOFS_FILE_MAP_SHIFT;
	int64_t span;
	int64_t roff;
	size_t slot;

	/*
	  Basic math:
	    slot / nslots == roff / span ==> slot == (roff * nslots) / span

	  However, need to do a right-shift to avoid integer-overflow.
	*/
	span = ftn_span(ftn) >> shift;
	roff = off_diff(ftn_beg(ftn), file_pos) >> shift;

	slot = (size_t)((roff * (long)nslots) / span);

	return slot;
}

static loff_t ftn_child(const struct silofs_ftree_node *ftn, size_t slot)
{
	loff_t off = 0;

	silofs_vaddr56_xtoh(&ftn->fn_child[slot], &off);
	return off;
}

static void
ftn_set_child(struct silofs_ftree_node *ftn, size_t slot, loff_t off)
{
	silofs_vaddr56_htox(&ftn->fn_child[slot], off);
}

static void ftn_reset_child(struct silofs_ftree_node *ftn, size_t slot)
{
	ftn_set_child(ftn, slot, SILOFS_OFF_NULL);
}

static bool ftn_has_child_at(const struct silofs_ftree_node *ftn, size_t slot)
{
	const loff_t voff = ftn_child(ftn, slot);

	return !off_isnull(voff);
}

static size_t ftn_nactive_childs(const struct silofs_ftree_node *ftn)
{
	return silofs_le32_to_cpu(ftn->fn_nactive_childs);
}

static void ftn_set_nactive_childs(struct silofs_ftree_node *ftn, size_t n)
{
	silofs_assert_le(n, ARRAY_SIZE(ftn->fn_child));

	ftn->fn_nactive_childs = silofs_cpu_to_le32((uint32_t)n);
}

static void ftn_inc_nactive_childs(struct silofs_ftree_node *ftn)
{
	ftn_set_nactive_childs(ftn, ftn_nactive_childs(ftn) + 1);
}

static void ftn_dec_nactive_childs(struct silofs_ftree_node *ftn)
{
	ftn_set_nactive_childs(ftn, ftn_nactive_childs(ftn) - 1);
}

static bool ftn_isinrange(const struct silofs_ftree_node *ftn, loff_t pos)
{
	return off_is_within(pos, ftn_beg(ftn), ftn_end(ftn));
}

static enum silofs_ltype ftn_child_ltype(const struct silofs_ftree_node *ftn)
{
	return (enum silofs_ltype)(ftn->fn_child_ltype);
}

static void
ftn_set_child_ltype(struct silofs_ftree_node *ftn, enum silofs_ltype ltype)
{
	ftn->fn_child_ltype = (uint8_t)(ltype);
}

static void
ftn_child_ltype_by_height(const struct silofs_ftree_node *ftn, size_t height,
                          enum silofs_ltype *out_child_ltype)
{
	if (height <= 2) {
		*out_child_ltype = SILOFS_LTYPE_DATABK;
	} else {
		*out_child_ltype = SILOFS_LTYPE_FTNODE;
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

static void ftn_calc_range(const struct silofs_ftree_node *ftn, loff_t off,
                           size_t height, loff_t *beg, loff_t *end)
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

static void ftn_init_null_childs(struct silofs_ftree_node *ftn)
{
	const size_t nslots_max = ftn_nchilds_max(ftn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		ftn_reset_child(ftn, slot);
	}
}

static void ftn_init(struct silofs_ftree_node *ftn, ino_t ino, loff_t beg,
                     loff_t end, size_t height, enum silofs_ltype child_ltype)
{
	ftn_set_refcnt(ftn, 0);
	ftn_set_ino(ftn, ino);
	ftn_set_beg(ftn, beg);
	ftn_set_end(ftn, end);
	ftn_set_nactive_childs(ftn, 0);
	ftn_set_height(ftn, height);
	ftn_set_child_ltype(ftn, child_ltype);
	ftn_init_null_childs(ftn);
	silofs_memzero(ftn->fn_zeros, sizeof(ftn->fn_zeros));
}

static void ftn_init_by(struct silofs_ftree_node *ftn, ino_t ino, loff_t off,
                        size_t height)
{
	loff_t beg;
	loff_t end;
	enum silofs_ltype child_ltype;

	ftn_child_ltype_by_height(ftn, height, &child_ltype);
	ftn_calc_range(ftn, off, height, &beg, &end);
	ftn_init(ftn, ino, beg, end, height, child_ltype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_file *infl_of(const struct silofs_inode *inode)
{
	const struct silofs_inode_file *infl = &inode->i_ta.f;

	return unconst(infl);
}

static size_t
infl_head1_slot_to_abs(const struct silofs_inode_file *infl, size_t head1_slot)
{
	STATICASSERT_GT(ARRAY_SIZE(infl->f_slots),
	                1 + SILOFS_FILE_HEAD2_NLEAF + SILOFS_FILE_HEAD1_NLEAF);
	silofs_assert_lt(head1_slot, SILOFS_FILE_HEAD1_NLEAF);

	return 1 + SILOFS_FILE_HEAD2_NLEAF + head1_slot;
}

static size_t
infl_head2_slot_to_abs(const struct silofs_inode_file *infl, size_t head2_slot)
{
	STATICASSERT_GT(ARRAY_SIZE(infl->f_slots),
	                1 + SILOFS_FILE_HEAD2_NLEAF + SILOFS_FILE_HEAD1_NLEAF);
	silofs_assert_lt(head2_slot, SILOFS_FILE_HEAD2_NLEAF);

	return 1 + head2_slot;
}

static void infl_head1_leaf(const struct silofs_inode_file *infl,
                            size_t head1_slot, struct silofs_vaddr *out_vaddr)
{
	const size_t slot = infl_head1_slot_to_abs(infl, head1_slot);

	silofs_vaddr64_xtoh(&infl->f_slots[slot], out_vaddr);
}

static void
infl_set_head1_leaf(struct silofs_inode_file *infl, size_t head1_slot,
                    const struct silofs_vaddr *vaddr)
{
	const size_t slot = infl_head1_slot_to_abs(infl, head1_slot);

	silofs_vaddr64_htox(&infl->f_slots[slot], vaddr);
}

static void infl_head2_leaf(const struct silofs_inode_file *infl,
                            size_t head2_slot, struct silofs_vaddr *out_vaddr)
{
	const size_t slot = infl_head2_slot_to_abs(infl, head2_slot);

	silofs_vaddr64_xtoh(&infl->f_slots[slot], out_vaddr);
}

static void
infl_set_head2_leaf(struct silofs_inode_file *infl, size_t head2_slot,
                    const struct silofs_vaddr *vaddr)
{
	const size_t slot = infl_head2_slot_to_abs(infl, head2_slot);

	silofs_vaddr64_htox(&infl->f_slots[slot], vaddr);
}

static void infl_tree_root(const struct silofs_inode_file *infl,
                           struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_xtoh(&infl->f_slots[0], out_vaddr);
}

static void infl_set_tree_root(struct silofs_inode_file *infl,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_htox(&infl->f_slots[0], vaddr);
}

static void infl_setup(struct silofs_inode_file *infl)
{
	const struct silofs_vaddr *vaddr = vaddr_none();

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD1_NLEAF; ++slot) {
		infl_set_head1_leaf(infl, slot, vaddr);
	}
	for (size_t slot = 0; slot < SILOFS_FILE_HEAD2_NLEAF; ++slot) {
		infl_set_head2_leaf(infl, slot, vaddr);
	}
	infl_set_tree_root(infl, vaddr);
}

static struct silofs_inode_file *ii_infl_of(const struct silofs_inode_info *ii)
{
	return infl_of(ii->inode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
fni_dirtify(struct silofs_finode_info *fni, struct silofs_inode_info *ii)
{
	vni_dirtify(&fni->fn_vni, ii);
}

static void fni_incref(struct silofs_finode_info *fni)
{
	if (likely(fni != NULL)) {
		vni_incref(&fni->fn_vni);
	}
}

static void fni_decref(struct silofs_finode_info *fni)
{
	if (likely(fni != NULL)) {
		vni_decref(&fni->fn_vni);
	}
}

static const struct silofs_vaddr *
fni_vaddr(const struct silofs_finode_info *fni)
{
	return vni_vaddr(&fni->fn_vni);
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

static void fni_assign_child_at(struct silofs_finode_info *fni, size_t slot,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_ftree_node *ftn = fni->ftn;
	const loff_t voff = vaddr->off;

	if (!ftn_has_child_at(ftn, slot)) {
		if (!off_isnull(voff)) {
			ftn_set_child(ftn, slot, voff);
			ftn_inc_nactive_childs(ftn);
		} else {
			ftn_reset_child(ftn, slot);
		}
	} else {
		if (!off_isnull(voff)) {
			ftn_set_child(ftn, slot, voff);
		} else {
			ftn_reset_child(ftn, slot);
			ftn_dec_nactive_childs(ftn);
		}
	}
}

static void fni_assign_child_by_pos(struct silofs_finode_info *fni, loff_t pos,
                                    const struct silofs_vaddr *vaddr)
{
	size_t child_slot;

	child_slot = fni_child_slot_of(fni, pos);
	fni_assign_child_at(fni, child_slot, vaddr);
}

static void fni_bind_child(struct silofs_finode_info *parent_fni,
                           loff_t file_pos, const struct silofs_vaddr *vaddr)
{
	if (parent_fni != NULL) {
		silofs_assert(!vaddr_isnull(vaddr));
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
	if (ftn_has_child_at(fni->ftn, slot)) {
		ftn_reset_child(fni->ftn, slot);
		ftn_dec_nactive_childs(fni->ftn);
	}
}

static void
fni_setup(struct silofs_finode_info *fni, const struct silofs_inode_info *ii,
          loff_t off, size_t height)
{
	ftn_init_by(fni->ftn, ii_ino(ii), off, height);
}

static void fni_resolve_child_by_slot(const struct silofs_finode_info *fni,
                                      size_t slot, struct silofs_vaddr *vaddr)
{
	const struct silofs_ftree_node *ftn = fni->ftn;

	vaddr_setup(vaddr, ftn_child_ltype(ftn), ftn_child(ftn, slot));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
	struct silofs_lblock *nil_bk = f_ctx->fsenv->fse.lcache->lc_nil_lbk;

	return nil_bk->u.bk;
}

static void filc_iovec_by_fileaf(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_fileaf_info *fli, bool all,
                                 struct silofs_iovec *out_iov)
{
	loff_t off_within;
	size_t len;

	if (all) {
		off_within = 0;
		len = fli_data_len(fli);
	} else {
		off_within = fli_off_within(fli, f_ctx->off);
		len = fli_len_within(fli, f_ctx->off, f_ctx->end);
	}

	silofs_iovec_reset(out_iov);
	out_iov->iov.iov_base = fli_data_at(fli, off_within);
	out_iov->iov.iov_len = len;
	out_iov->iov_backref = f_ctx->with_backref ? fli : NULL;
}

static void filc_iovec_by_nilbk(const struct silofs_file_ctx *f_ctx,
                                const enum silofs_ltype ltype,
                                struct silofs_iovec *out_iov)
{
	silofs_iovec_reset(out_iov);
	out_iov->iov.iov_base = filc_nil_block(f_ctx);
	out_iov->iov.iov_len = len_of_data(f_ctx->off, f_ctx->end, ltype);
	out_iov->iov_off = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_require_mut_vaddr(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_COW;

	return silofs_resolve_llink_of(f_ctx->task, vaddr, stg_mode, &llink);
}

static size_t filc_io_length(const struct silofs_file_ctx *f_ctx)
{
	return off_ulen(f_ctx->beg, f_ctx->off);
}

static bool filc_has_more_io(const struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->off < f_ctx->end) && !f_ctx->fm_stop &&
	       !f_ctx->task->t_interrupt;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void flref_reset(struct silofs_fileaf_ref *flref)
{
	silofs_memzero(flref, sizeof(*flref));
	vaddr_reset(&flref->vaddr);
	laddr_reset(&flref->laddr);
}

static void
flref_setup(struct silofs_fileaf_ref *flref,
            const struct silofs_inode_info *ii,
            struct silofs_finode_info *parent_fni,
            const struct silofs_vaddr *vaddr, loff_t file_pos, loff_t io_end)
{
	const bool ftype2 = ii_isftype2(ii);

	flref_reset(flref);
	vaddr_assign(&flref->vaddr, vaddr);
	flref->ii = ii;
	flref->parent_fni = parent_fni;
	flref->slot_idx = UINT_MAX;
	flref->file_pos = file_pos;
	flref->has_data = !vaddr_isnull(vaddr);
	flref->has_hole = !flref->has_data;
	flref->shared = false;
	flref->unwritten = true;

	if (!ftype2 && off_is_head1(file_pos)) {
		flref->head1 = true;
		flref->slot_idx = off_to_head1_slot(file_pos);
		flref->partial = off_is_partial_head1(file_pos, io_end);
		flref->leaf_size = SILOFS_FILE_HEAD1_LEAF_SIZE;
	} else if (!ftype2 && off_is_head2(file_pos)) {
		flref->head2 = true;
		flref->slot_idx = off_to_head2_slot(file_pos);
		flref->partial = off_is_partial_head2(file_pos, io_end);
		flref->leaf_size = SILOFS_FILE_HEAD2_LEAF_SIZE;
	} else {
		flref->tree = true;
		flref->slot_idx = off_to_leaf_slot(file_pos);
		flref->partial = off_is_partial_leaf(file_pos, io_end);
		flref->leaf_size = SILOFS_FILE_TREE_LEAF_SIZE;
	}
}

static void
flref_noent(struct silofs_fileaf_ref *flref,
            const struct silofs_inode_info *ii, loff_t file_pos, loff_t io_end)
{
	flref_setup(flref, ii, NULL, vaddr_none(), file_pos, io_end);
}

static void flref_update_partial(struct silofs_fileaf_ref *flref, size_t len)
{
	if (len > 0) {
		flref->partial = (len < flref->leaf_size);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool filc_ftype1_mode(const struct silofs_file_ctx *f_ctx)
{
	return ii_isftype1(f_ctx->ii);
}

static void
filc_resolve_child_at(const struct silofs_file_ctx *f_ctx,
                      struct silofs_finode_info *fni, loff_t file_pos,
                      size_t slot, struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;

	fni_resolve_child_by_slot(fni, slot, &vaddr);
	flref_setup(out_flref, f_ctx->ii, fni, &vaddr, file_pos, f_ctx->end);
}

static void filc_resolve_child(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni, loff_t file_pos,
                               struct silofs_fileaf_ref *out_flref)
{
	size_t slot;

	if (fni != NULL) {
		slot = fni_child_slot_of(fni, file_pos);
		filc_resolve_child_at(f_ctx, fni, file_pos, slot, out_flref);
	} else {
		flref_setup(out_flref, f_ctx->ii, NULL, vaddr_none(), file_pos,
		            f_ctx->end);
	}
}

static void filc_resolve_child_of(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *fni,
                                  struct silofs_vaddr *out_vaddr)
{
	size_t slot;

	vaddr_reset(out_vaddr);
	if (fni != NULL) {
		slot = fni_child_slot_of(fni, f_ctx->off);
		fni_resolve_child_by_slot(fni, slot, out_vaddr);
	}
}

static bool filc_has_head1_leaves_io(const struct silofs_file_ctx *f_ctx)
{
	return filc_ftype1_mode(f_ctx) && filc_has_more_io(f_ctx) &&
	       off_is_head1(f_ctx->off);
}

static bool filc_has_head2_leaves_io(const struct silofs_file_ctx *f_ctx)
{
	return filc_ftype1_mode(f_ctx) && filc_has_more_io(f_ctx) &&
	       off_is_head2(f_ctx->off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t filc_head1_leaf_slot_of(const struct silofs_file_ctx *f_ctx)
{
	return off_to_head1_slot(f_ctx->off);
}

static void filc_head1_leaf_at(const struct silofs_file_ctx *f_ctx,
                               size_t slot, struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_head1_leaf(infl, slot, out_vaddr);
}

static void filc_resolve_head1_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	const size_t slot = filc_head1_leaf_slot_of(f_ctx);

	filc_head1_leaf_at(f_ctx, slot, &vaddr);
	flref_setup(out_flref, f_ctx->ii, NULL, &vaddr, f_ctx->off,
	            f_ctx->end);
}

static void
filc_set_head1_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_set_head1_leaf(infl, slot, vaddr);
}

static size_t filc_head2_leaf_slot_of(const struct silofs_file_ctx *f_ctx)
{
	return off_to_head2_slot(f_ctx->off);
}

static void filc_head2_leaf_at(const struct silofs_file_ctx *f_ctx,
                               size_t slot, struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_head2_leaf(infl, slot, out_vaddr);
}

static void filc_resolve_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	const size_t slot = filc_head2_leaf_slot_of(f_ctx);

	filc_head2_leaf_at(f_ctx, slot, &vaddr);
	flref_setup(out_flref, f_ctx->ii, NULL, &vaddr, f_ctx->off,
	            f_ctx->end);
}

static void
filc_set_head2_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_set_head2_leaf(infl, slot, vaddr);
}

static void filc_tree_root_of(const struct silofs_file_ctx *f_ctx,
                              struct silofs_vaddr *out_vaddr)
{
	const struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_tree_root(infl, out_vaddr);
}

static bool filc_has_tree_root(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_vaddr vaddr;

	filc_tree_root_of(f_ctx, &vaddr);
	return ltype_isftnode(vaddr.ltype);
}

static void filc_set_tree_root_at(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_file *infl = ii_infl_of(f_ctx->ii);

	infl_set_tree_root(infl, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filc_curr_data_ltype(const struct silofs_file_ctx *f_ctx,
                                 enum silofs_ltype *out_ltype)
{
	*out_ltype = SILOFS_LTYPE_DATABK;
	if (filc_ftype1_mode(f_ctx)) {
		if (off_is_head1(f_ctx->off)) {
			*out_ltype = SILOFS_LTYPE_DATA1K;
		} else if (off_is_head2(f_ctx->off)) {
			*out_ltype = SILOFS_LTYPE_DATA4K;
		}
	}
}

static size_t filc_distance_to_next(const struct silofs_file_ctx *f_ctx)
{
	enum silofs_ltype ltype;

	filc_curr_data_ltype(f_ctx, &ltype);
	return len_to_next(f_ctx->off, ltype);
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

static void
filc_advance_by_nbytes2(struct silofs_file_ctx *f_ctx1,
                        struct silofs_file_ctx *f_ctx2, ssize_t len)
{
	if (len > 0) {
		filc_advance_by_nbytes(f_ctx1, (size_t)len);
		filc_advance_by_nbytes(f_ctx2, (size_t)len);
	}
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
	enum silofs_file_type ftype;

	if (ii_isdir(f_ctx->ii)) {
		return -SILOFS_EISDIR;
	}
	ftype = ii_ftype(f_ctx->ii);
	if ((ftype != SILOFS_FILE_TYPE1) && (ftype != SILOFS_FILE_TYPE2)) {
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
	if ((f_ctx->op_mask & OP_WRITE) && f_ctx->o_flags) {
		if (!(f_ctx->o_flags & (O_RDWR | O_WRONLY))) {
			return -SILOFS_EPERM;
		}
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
		if (!off_is_lbk_aligned(f_ctx->beg) &&
		    (f_ctx->len > SILOFS_IO_SIZE_MAX)) {
			return -SILOFS_EINVAL;
		}
	}
	if (f_ctx->o_flags & O_DIRECTORY) {
		return -SILOFS_ENOTDIR;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni,
                                    struct silofs_fileaf_ref *out_flref);

static bool filc_ismapping_boundaries(const struct silofs_file_ctx *f_ctx)
{
	const loff_t mapping_size =
		(SILOFS_FILE_TREE_LEAF_SIZE * SILOFS_FILE_NODE_NCHILDS);

	return ((f_ctx->off % mapping_size) == 0);
}

static void
filc_update_post_io(const struct silofs_file_ctx *f_ctx, bool kill_suid_sgid)
{
	struct silofs_iattr iattr;
	struct silofs_inode_info *ii = f_ctx->ii;
	const loff_t isz = ii_size(ii);
	const loff_t isp = ii_span(ii);
	const loff_t off = f_ctx->off;
	const loff_t end = f_ctx->end;
	const size_t len = filc_io_length(f_ctx);

	ii_mkiattr(ii, &iattr);
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

	ii_update_iattrs(ii, task_creds(f_ctx->task), &iattr);
}

static int filc_update_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fileaf_ref *flref)
{
	flref->unwritten = true;
	return vaddr_isnull(&flref->vaddr) ?
	               0 :
	               silofs_test_unwritten_at(f_ctx->task, &flref->vaddr,
	                                        &flref->unwritten);
}

static int
filc_update_pre_write_leaf_by(const struct silofs_file_ctx *f_ctx,
                              struct silofs_fileaf_ref *flref, size_t len)
{
	flref_update_partial(flref, len);
	return filc_update_unwritten_by(f_ctx, flref);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_recheck_fileaf(const struct silofs_file_ctx *f_ctx,
                               struct silofs_fileaf_info *fli)
{
	if (!vni_need_recheck(&fli->fl_vni)) {
		return 0;
	}
	silofs_unused(f_ctx);
	vni_set_rechecked(&fli->fl_vni);
	return 0;
}

static int filc_stage_fileaf(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_fileaf_info **out_fli)
{
	struct silofs_vnode_info *vni = NULL;
	struct silofs_fileaf_info *fli = NULL;
	int err;

	err = silofs_stage_vnode(f_ctx->task, f_ctx->ii, vaddr,
	                         f_ctx->stg_mode, &vni);
	if (err) {
		return err;
	}
	fli = silofs_fli_from_vni(vni);
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

static int filc_zero_data_leaf_range(const struct silofs_file_ctx *f_ctx,
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

static int filc_recheck_fni(const struct silofs_file_ctx *f_ctx,
                            struct silofs_finode_info *fni)
{
	ino_t fnode_ino;
	ino_t owner_ino;
	size_t height;

	if (!vni_need_recheck(&fni->fn_vni)) {
		return 0;
	}
	fnode_ino = ftn_ino(fni->ftn);
	owner_ino = ii_ino(f_ctx->ii);
	if (fnode_ino != owner_ino) {
		log_err("bad finode ino: fnode_ino=%lu owner_ino=%lu",
		        fnode_ino, owner_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	height = ftn_height(fni->ftn);
	if ((height < 2) || (height > 16)) {
		log_err("illegal height: height=%lu ino=%lu", height,
		        owner_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	vni_set_rechecked(&fni->fn_vni);
	return 0;
}

static int filc_stage_tree_node(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_finode_info **out_fni)
{
	struct silofs_vnode_info *vni = NULL;
	struct silofs_finode_info *fni = NULL;
	int err;

	err = silofs_stage_vnode(f_ctx->task, f_ctx->ii, vaddr,
	                         f_ctx->stg_mode, &vni);
	if (err) {
		return err;
	}
	fni = silofs_fni_from_vni(vni);
	err = filc_recheck_fni(f_ctx, fni);
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
	return filc_stage_tree_node(f_ctx, &root_vaddr, out_fni);
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
                                    struct silofs_fileaf_ref *out_flref)
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
		filc_resolve_child_at(f_ctx, parent_fni, f_ctx->off, slot,
		                      out_flref);
		if (seek_hole == out_flref->has_hole) {
			return 0;
		}
	}
	return -SILOFS_ENOENT;
}

static int
filc_seek_tree_recursive_at(struct silofs_file_ctx *f_ctx,
                            struct silofs_finode_info *parent_fni, size_t slot,
                            struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	struct silofs_finode_info *fni = NULL;
	int err;

	fni_resolve_child_by_slot(parent_fni, slot, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_node(f_ctx, &vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_seek_tree_recursive(f_ctx, fni, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_do_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_finode_info *parent_fni,
                                       struct silofs_fileaf_ref *out_flref)
{
	const size_t nslots_max = fni_nchilds_max(parent_fni);
	size_t start_slot;
	int ret;

	if (!fni_isinrange(parent_fni, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}
	if (fni_isbottom(parent_fni)) {
		return filc_seek_tree_at_leaves(f_ctx, parent_fni, out_flref);
	}
	ret = filc_is_seek_hole(f_ctx) ? 0 : -SILOFS_ENOENT;
	start_slot = fni_child_slot_of(parent_fni, f_ctx->off);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		ret = filc_seek_tree_recursive_at(f_ctx, parent_fni, slot,
		                                  out_flref);
		if (ret != -SILOFS_ENOENT) {
			break;
		}
		filc_advance_to_next_tree_slot(f_ctx, parent_fni, slot);
	}
	return ret;
}

static int filc_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                    struct silofs_finode_info *parent_fni,
                                    struct silofs_fileaf_ref *out_flref)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_seek_tree_recursive(f_ctx, parent_fni, out_flref);
	fni_decref(parent_fni);
	return ret;
}

static int filc_seek_by_tree(struct silofs_file_ctx *f_ctx,
                             struct silofs_fileaf_ref *out_flref)
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
	err = filc_seek_tree_recursive(f_ctx, root_fni, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_seek_data_by_heads(struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_ref *out_flref)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_flref);
		if (out_flref->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_flref);
		if (out_flref->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_seek_hole_by_heads(struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_ref *out_flref)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_flref);
		if (out_flref->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_flref);
		if (out_flref->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static void filc_resolve_iovec(const struct silofs_file_ctx *f_ctx,
                               struct silofs_fileaf_info *fli,
                               struct silofs_iovec *out_iov)
{
	enum silofs_ltype ltype;

	if (fli != NULL) {
		filc_iovec_by_fileaf(f_ctx, fli, false, out_iov);
	} else {
		filc_curr_data_ltype(f_ctx, &ltype);
		filc_iovec_by_nilbk(f_ctx, ltype, out_iov);
	}
}

static void iovref_pre(const struct silofs_iovec *iov, int wr_mode)
{
	struct silofs_fileaf_info *fli = iov->iov_backref;

	if (fli != NULL) {
		fli_pre_io(fli, wr_mode);
	}
}

static void iovref_post(const struct silofs_iovec *iov, int wr_mode)
{
	struct silofs_fileaf_info *fli = iov->iov_backref;

	if (fli != NULL) {
		fli_post_io(fli, wr_mode);
	}
}

static int filc_call_rw_actor(const struct silofs_file_ctx *f_ctx,
                              struct silofs_fileaf_info *fli, size_t *out_len)
{
	struct silofs_iovec iovec = {
		.iov.iov_base = NULL,
		.iov.iov_len = 0,
		.iov_backref = NULL,
		.iov_off = -1,
		.iov_fd = -1,
	};
	int wr_mode = f_ctx->op_mask & OP_WRITE;
	int err;

	filc_resolve_iovec(f_ctx, fli, &iovec);
	iovref_pre(&iovec, wr_mode);
	err = f_ctx->rwi_ctx->actor(f_ctx->rwi_ctx, &iovec);
	*out_len = iovec.iov.iov_len;
	if (err) {
		iovref_post(&iovec, wr_mode);
		return err;
	}
	return 0;
}

static int
filc_export_data_by_fileaf(const struct silofs_file_ctx *f_ctx,
                           struct silofs_fileaf_info *fli, size_t *out_sz)
{
	return filc_call_rw_actor(f_ctx, fli, out_sz);
}

static int
filc_export_data_by_curr(struct silofs_file_ctx *f_ctx, size_t *out_sz)
{
	return filc_call_rw_actor(f_ctx, NULL, out_sz);
}

static int
filc_import_data_by_fileaf(const struct silofs_file_ctx *f_ctx,
                           struct silofs_fileaf_info *fli, size_t *out_sz)
{
	int err;

	err = filc_call_rw_actor(f_ctx, fli, out_sz);
	if (!err) {
		filc_dirtify_fileaf(f_ctx, fli);
	}
	return err;
}

static void filc_child_of_current_pos(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni,
                                      struct silofs_fileaf_ref *out_flref)
{
	filc_resolve_child(f_ctx, parent_fni, f_ctx->off, out_flref);
}

static void filc_resolve_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_finode_info *parent_fni,
                                   struct silofs_fileaf_ref *out_flref)
{
	filc_child_of_current_pos(f_ctx, parent_fni, out_flref);
}

static void filc_resolve_tree_node(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_finode_info *parent_fni,
                                   struct silofs_vaddr *out_vaddr)
{
	filc_resolve_child_of(f_ctx, parent_fni, out_vaddr);
}

static int filc_do_stage_by_tree_from(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *root_fni,
                                      struct silofs_finode_info **out_fni)
{
	struct silofs_finode_info *fni = root_fni;
	struct silofs_vaddr vaddr;
	size_t height;
	int err;

	height = fni_height(fni);
	while (height--) {
		if (fni_isbottom(fni)) {
			*out_fni = fni;
			return 0;
		}
		filc_resolve_tree_node(f_ctx, fni, &vaddr);
		err = filc_stage_tree_node(f_ctx, &vaddr, &fni);
		if (err) {
			return err;
		}
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_stage_by_tree_from(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_finode_info *root_fni,
                                   struct silofs_finode_info **out_fni)
{
	int ret;

	fni_incref(root_fni);
	ret = filc_do_stage_by_tree_from(f_ctx, root_fni, out_fni);
	fni_decref(root_fni);
	return ret;
}

static int filc_stage_by_tree(const struct silofs_file_ctx *f_ctx,
                              struct silofs_finode_info **out_fni)
{
	struct silofs_finode_info *root_fni = NULL;
	int err;

	*out_fni = NULL;
	if (!filc_has_tree_root(f_ctx)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_root(f_ctx, &root_fni);
	if (err) {
		return err;
	}
	if (!fni_isinrange(root_fni, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_by_tree_from(f_ctx, root_fni, out_fni);
	if (err) {
		return err;
	}
	return 0;
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
	return filc_export_data_by_curr(f_ctx, out_sz);
}

static int filc_stage_fileaf_by(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_fileaf_ref *flref,
                                struct silofs_fileaf_info **out_fli)
{
	int ret = -SILOFS_ENOENT;

	*out_fli = NULL;
	if (flref->has_data) {
		ret = filc_stage_fileaf(f_ctx, &flref->vaddr, out_fli);
	}
	return ret;
}

static int
filc_read_from_leaf(struct silofs_file_ctx *f_ctx,
                    struct silofs_fileaf_ref *flref, size_t *out_len)
{
	struct silofs_fileaf_info *fli = NULL;
	int err;

	*out_len = 0;
	err = filc_update_unwritten_by(f_ctx, flref);
	if (err) {
		return err;
	}
	if (flref->unwritten) {
		err = filc_read_leaf_as_zeros(f_ctx, out_len);
		if (err) {
			return err;
		}
	} else {
		err = filc_stage_fileaf_by(f_ctx, flref, &fli);
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

static int filc_do_read_from_tree_leaves(struct silofs_file_ctx *f_ctx,
                                         struct silofs_finode_info *parent_fni)
{
	struct silofs_fileaf_ref flref;
	size_t len = 0;
	int err;

	while (filc_has_more_io(f_ctx)) {
		filc_resolve_tree_leaf(f_ctx, parent_fni, &flref);
		err = filc_read_from_leaf(f_ctx, &flref, &len);
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

static int filc_read_by_tree(struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *parent_fni = NULL;
	int err;

	while (filc_has_more_io(f_ctx)) {
		parent_fni = NULL;
		err = filc_stage_by_tree(f_ctx, &parent_fni);
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

static int filc_read_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	size_t len;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, &flref);
		err = filc_read_from_leaf(f_ctx, &flref, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, &flref);
		err = filc_read_from_leaf(f_ctx, &flref, &len);
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

	err = filc_read_by_heads(f_ctx);
	if (err) {
		return err;
	}
	err = filc_read_by_tree(f_ctx);
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
                           const struct silofs_iovec *iovec)
{
	struct silofs_read_iter *rdi = read_iter_of(rwi);
	int err;

	if ((iovec->iov_fd > 0) && (iovec->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if ((rdi->dat_len + iovec->iov.iov_len) > rdi->dat_max) {
		return -SILOFS_EINVAL;
	}
	err = silofs_iovec_copy_into(iovec, rdi->dat + rdi->dat_len);
	if (err) {
		return err;
	}
	rdi->dat_len += iovec->iov.iov_len;
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
                        int o_flags, struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 1,
		.o_flags = o_flags,
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
                   void *buf, size_t len, loff_t off, int o_flags,
                   size_t *out_len)
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
		.fsenv = task->t_fsenv,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 0,
		.o_flags = o_flags,
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

static int
filc_claim_vspace(const struct silofs_file_ctx *f_ctx, enum silofs_ltype ltype,
                  struct silofs_vaddr *out_vaddr)
{
	return silofs_claim_vspace(f_ctx->task, ltype, out_vaddr);
}

static int
filc_claim_data_space(const struct silofs_file_ctx *f_ctx,
                      enum silofs_ltype ltype, struct silofs_vaddr *out_vaddr)
{
	int err;

	err = filc_claim_vspace(f_ctx, ltype, out_vaddr);
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
	err = silofs_remove_vnode_at(f_ctx->task, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_spawn_finode(const struct silofs_file_ctx *f_ctx,
                             struct silofs_finode_info **out_fni)
{
	struct silofs_vnode_info *vni = NULL;
	struct silofs_finode_info *fni = NULL;
	int err;

	err = silofs_spawn_vnode(f_ctx->task, f_ctx->ii, SILOFS_LTYPE_FTNODE,
	                         &vni);
	if (err) {
		return err;
	}
	fni = silofs_fni_from_vni(vni);
	fni_dirtify(fni, f_ctx->ii);
	*out_fni = fni;
	return 0;
}

static int filc_remove_finode(const struct silofs_file_ctx *f_ctx,
                              struct silofs_finode_info *fni)
{
	return silofs_remove_vnode(f_ctx->task, &fni->fn_vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filc_update_head1_leaf_by(const struct silofs_file_ctx *f_ctx,
                                      const struct silofs_fileaf_ref *flref)
{
	filc_set_head1_leaf_at(f_ctx, flref->slot_idx, &flref->vaddr);
	ii_dirtify(f_ctx->ii);
}

static void filc_update_head2_leaf_by(const struct silofs_file_ctx *f_ctx,
                                      const struct silofs_fileaf_ref *flref)
{
	filc_set_head2_leaf_at(f_ctx, flref->slot_idx, &flref->vaddr);
	ii_dirtify(f_ctx->ii);
}

static void filc_update_tree_root(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	filc_set_tree_root_at(f_ctx, vaddr);
	ii_dirtify(f_ctx->ii);
}

static void filc_update_iblocks(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_vaddr *vaddr, long dif)
{
	silofs_ii_update_iblocks(f_ctx->ii, task_creds(f_ctx->task),
	                         vaddr->ltype, dif);
}

static int
filc_spawn_setup_finode(const struct silofs_file_ctx *f_ctx, loff_t off,
                        size_t height, struct silofs_finode_info **out_fni)
{
	int err;

	err = filc_spawn_finode(f_ctx, out_fni);
	if (err) {
		return err;
	}
	fni_setup(*out_fni, f_ctx->ii, off, height);
	fni_dirtify(*out_fni, f_ctx->ii);
	return 0;
}

static int
filc_spawn_root_finode(const struct silofs_file_ctx *f_ctx, size_t height,
                       struct silofs_finode_info **out_fni)
{
	silofs_assert_ge(height, 2);

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
	fni_dirtify(parent_fni, f_ctx->ii);
	return 0;
}

static int
filc_create_data_leaf(const struct silofs_file_ctx *f_ctx,
                      enum silofs_ltype ltype, struct silofs_vaddr *out_vaddr)
{
	int err;

	err = filc_claim_data_space(f_ctx, ltype, out_vaddr);
	if (err) {
		return err;
	}
	filc_update_iblocks(f_ctx, out_vaddr, 1);
	return 0;
}

static int filc_create_head1_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_LTYPE_DATA1K, &vaddr);
	if (err) {
		return err;
	}
	flref_setup(out_flref, f_ctx->ii, NULL, &vaddr, f_ctx->off,
	            f_ctx->end);
	filc_update_head1_leaf_by(f_ctx, out_flref);
	return 0;
}

static int filc_create_head2_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_LTYPE_DATA4K, &vaddr);
	if (err) {
		return err;
	}
	flref_setup(out_flref, f_ctx->ii, NULL, &vaddr, f_ctx->off,
	            f_ctx->end);
	filc_update_head2_leaf_by(f_ctx, out_flref);
	return 0;
}

static int
filc_do_create_tree_leaf_space(const struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni)
{
	struct silofs_vaddr vaddr;
	int err;

	err = filc_create_data_leaf(f_ctx, SILOFS_LTYPE_DATABK, &vaddr);
	if (err) {
		return err;
	}
	fni_bind_child(parent_fni, f_ctx->off, &vaddr);
	fni_dirtify(parent_fni, f_ctx->ii);
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
	fni_assign_child_at(fni, 0, &vaddr);
	fni_dirtify(fni, f_ctx->ii);

	filc_update_tree_root(f_ctx, fni_vaddr(fni));
	fni_bind_finode(NULL, 0, fni);
}

static int filc_resolve_tree_root(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info **out_fni)
{
	return filc_has_tree_root(f_ctx) ?
	               filc_stage_tree_root(f_ctx, out_fni) :
	               0;
}

static int filc_create_tree_spine(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_finode_info *fni = NULL;
	size_t height_want;
	size_t height_curr;
	int err;

	err = filc_resolve_tree_root(f_ctx, &fni);
	if (err) {
		return err;
	}
	height_want = off_to_tree_height(f_ctx->off);
	height_curr = fni ? fni_height(fni) : 1;
	while (height_curr < height_want) {
		err = filc_spawn_root_finode(f_ctx, ++height_curr, &fni);
		if (err) {
			return err;
		}
		filc_bind_sub_tree(f_ctx, fni);
	}
	return 0;
}

static int filc_do_require_tree_node(const struct silofs_file_ctx *f_ctx,
                                     struct silofs_finode_info *parent_fni,
                                     struct silofs_finode_info **out_fni)
{
	struct silofs_vaddr vaddr;
	int ret;

	filc_resolve_tree_node(f_ctx, parent_fni, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		ret = filc_stage_tree_node(f_ctx, &vaddr, out_fni);
	} else {
		ret = filc_spawn_bind_finode(f_ctx, parent_fni, out_fni);
	}
	return ret;
}

static int filc_require_tree_node(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *parent_fni,
                                  struct silofs_finode_info **out_fni)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_require_tree_node(f_ctx, parent_fni, out_fni);
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
		err = filc_require_tree_node(f_ctx, fni, &fni);
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

static int filc_pre_write_leaf(const struct silofs_file_ctx *f_ctx,
                               struct silofs_fileaf_ref *flref, size_t len)
{
	int err;

	err = filc_update_pre_write_leaf_by(f_ctx, flref, len);
	if (err) {
		return err;
	}
	if (!flref->unwritten || !flref->partial) {
		return 0;
	}
	err = filc_zero_data_leaf_at(f_ctx, &flref->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_require_mut_by(const struct silofs_file_ctx *f_ctx,
                               const struct silofs_fileaf_ref *flref)
{
	return vaddr_isnull(&flref->vaddr) ?
	               0 :
	               filc_require_mut_vaddr(f_ctx, &flref->vaddr);
}

static int filc_do_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                     struct silofs_finode_info *parent_fni,
                                     struct silofs_fileaf_ref *out_flref)
{
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fni, out_flref);
	if (out_flref->has_data) {
		return filc_require_mut_by(f_ctx, out_flref);
	}
	err = filc_create_tree_leaf_space(f_ctx, parent_fni);
	if (err) {
		return err;
	}
	filc_resolve_tree_leaf(f_ctx, parent_fni, out_flref);
	return 0;
}

static int filc_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_finode_info *parent_fni,
                                  struct silofs_fileaf_ref *out_flref)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_require_tree_leaf(f_ctx, parent_fni, out_flref);
	fni_decref(parent_fni);
	return ret;
}

static int
filc_write_to_leaf_by(const struct silofs_file_ctx *f_ctx,
                      struct silofs_fileaf_ref *flref, size_t *out_len)
{
	struct silofs_fileaf_info *fli = NULL;
	int err;

	err = filc_pre_write_leaf(f_ctx, flref, 0);
	if (err) {
		return err;
	}
	err = filc_stage_fileaf_by(f_ctx, flref, &fli);
	if (err) {
		return err;
	}
	err = filc_write_leaf_by_copy(f_ctx, fli, out_len);
	if (err) {
		return err;
	}
	flref->unwritten = false;
	return 0;
}

static int filc_detect_shared_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_fileaf_ref *flref)
{
	int ret = 0;

	if (flref->tree && flref->has_data && !flref->shared) {
		ret = silofs_test_shared_dbkref(f_ctx->task, &flref->vaddr,
		                                &flref->shared);
	}
	return ret;
}

static int filc_do_write_to_tree_leaves(struct silofs_file_ctx *f_ctx,
                                        struct silofs_finode_info *parent_fni)
{
	struct silofs_fileaf_ref flref = { .file_pos = -1 };
	size_t len;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_require_tree_leaf(f_ctx, parent_fni, &flref);
		if (err) {
			return err;
		}
		err = filc_detect_shared_by(f_ctx, &flref);
		if (err) {
			return err;
		}
		err = filc_unshare_leaf_by(f_ctx, &flref);
		if (err) {
			return err;
		}
		len = 0;
		err = filc_write_to_leaf_by(f_ctx, &flref, &len);
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

static int filc_write_by_tree(struct silofs_file_ctx *f_ctx)
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
                                   struct silofs_fileaf_ref *out_flref)
{
	int err;

	filc_resolve_head1_leaf(f_ctx, out_flref);
	if (out_flref->has_data) {
		return filc_require_mut_by(f_ctx, out_flref);
	}
	err = filc_create_head1_leaf_space(f_ctx, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_require_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_ref *out_flref)
{
	int err;

	filc_resolve_head2_leaf(f_ctx, out_flref);
	if (out_flref->has_data) {
		return filc_require_mut_by(f_ctx, out_flref);
	}
	err = filc_create_head2_leaf_space(f_ctx, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_write_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	size_t len = 0;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		err = filc_require_head1_leaf(f_ctx, &flref);
		if (err) {
			return err;
		}
		len = 0;
		err = filc_write_to_leaf_by(f_ctx, &flref, &len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx, len);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		err = filc_require_head2_leaf(f_ctx, &flref);
		if (err) {
			return err;
		}
		len = 0;
		err = filc_write_to_leaf_by(f_ctx, &flref, &len);
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

	err = filc_write_by_heads(f_ctx);
	if (err) {
		return err;
	}
	err = filc_write_by_tree(f_ctx);
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
                            const struct silofs_iovec *iovec)
{
	struct silofs_write_iter *wri = write_iter_of(rwi);
	int err;

	if ((iovec->iov_fd > 0) && (iovec->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if ((wri->dat_len + iovec->iov.iov_len) > wri->dat_max) {
		return -SILOFS_EINVAL;
	}
	err = silofs_iovec_copy_from(iovec, wri->dat + wri->dat_len);
	if (err) {
		return err;
	}
	wri->dat_len += iovec->iov.iov_len;
	return 0;
}

static int filc_flush_dirty_of(const struct silofs_file_ctx *f_ctx, int flags)
{
	return silofs_flush_dirty(f_ctx->task, f_ctx->ii, flags);
}

static int filc_flush_dirty_now(const struct silofs_file_ctx *f_ctx)
{
	return filc_flush_dirty_of(f_ctx, SILOFS_F_NOW);
}

static int filc_post_write_iter(const struct silofs_file_ctx *f_ctx)
{
	int ret = 0;

	if (f_ctx->o_flags & (O_SYNC | O_DSYNC)) {
		ret = filc_flush_dirty_of(f_ctx, SILOFS_F_FSYNC);
	}
	return ret;
}

static int filc_write_iter(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = filc_write_data(f_ctx);
	if (err) {
		goto out;
	}
	err = filc_post_write_iter(f_ctx);
	if (err) {
		goto out;
	}
out:
	filc_update_post_io(f_ctx, !err && (f_ctx->off > f_ctx->beg));
	return err;
}

int silofs_do_write_iter(struct silofs_task *task,
                         struct silofs_inode_info *ii, int o_flags,
                         struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_WRITE,
		.with_backref = 1,
		.o_flags = o_flags,
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
                    const void *buf, size_t len, loff_t off, int o_flags,
                    size_t *out_len)
{
	struct silofs_write_iter wri = {
		.rwi.actor = write_iter_actor,
		.rwi.len = len,
		.rwi.off = off,
		.dat = buf,
		.dat_len = 0,
		.dat_max = len,
	};
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
		.sbi = task_sbi(task),
		.ii = ii,
		.op_mask = OP_WRITE,
		.with_backref = 0,
		.o_flags = o_flags,
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
	filc_update_iblocks(f_ctx, vaddr, -1);
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
	err = filc_stage_tree_node(f_ctx, vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_drop_remove_subtree(f_ctx, fni);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_drop_subtree_at(struct silofs_file_ctx *f_ctx,
                                struct silofs_finode_info *fni, size_t slot)
{
	struct silofs_vaddr vaddr;
	int err;

	fni_resolve_child_by_slot(fni, slot, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return 0;
	}
	if (fni_isbottom(fni)) {
		err = filc_discard_data_leaf(f_ctx, &vaddr);
	} else {
		err = filc_drop_subtree(f_ctx, &vaddr);
	}
	if (err) {
		return err;
	}
	fni_clear_subtree_mappings(fni, slot);
	return 0;
}

static int filc_drop_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *fni)
{
	const size_t nslots_max = ftn_nchilds_max(fni->ftn);
	int err = 0;

	fni_incref(fni);
	for (size_t slot = 0; slot < nslots_max; ++slot) {
		if (!ftn_nactive_childs(fni->ftn)) {
			break;
		}
		err = filc_drop_subtree_at(f_ctx, fni, slot);
		if (err) {
			break;
		}
	}
	fni_decref(fni);
	return err;
}

static int
filc_drop_finode(struct silofs_file_ctx *f_ctx, struct silofs_finode_info *fni)
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

static void filc_reset_head1_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_fileaf_ref *flref)
{
	filc_reset_head1_leaf_at(f_ctx, flref->slot_idx);
}

static void filc_reset_head2_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_fileaf_ref *flref)
{
	filc_reset_head2_leaf_at(f_ctx, flref->slot_idx);
}

static void
filc_clear_subtree_mappings_by(const struct silofs_file_ctx *f_ctx,
                               const struct silofs_fileaf_ref *flref)
{
	fni_clear_subtree_mappings(flref->parent_fni, flref->slot_idx);
	fni_dirtify(flref->parent_fni, f_ctx->ii);
}

static int filc_drop_head1_leafs(struct silofs_file_ctx *f_ctx)
{
	int err;

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD1_NLEAF; ++slot) {
		err = filc_drop_head1_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		filc_reset_head1_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int filc_drop_head2_leafs(struct silofs_file_ctx *f_ctx)
{
	int err;

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD2_NLEAF; ++slot) {
		err = filc_drop_head2_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		filc_reset_head2_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int filc_drop_heads(struct silofs_file_ctx *f_ctx)
{
	int err;

	if (!filc_ftype1_mode(f_ctx)) {
		return 0;
	}
	err = filc_drop_head1_leafs(f_ctx);
	if (err) {
		return err;
	}
	err = filc_drop_head2_leafs(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_drop_data_and_meta(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_drop_heads(f_ctx);
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
		.fsenv = task->t_fsenv,
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

static int filc_zero_data_leaf_range_by(const struct silofs_file_ctx *f_ctx,
                                        const struct silofs_fileaf_ref *flref)
{
	const struct silofs_vaddr *vaddr = &flref->vaddr;
	const loff_t pos = flref->file_pos;
	const size_t len = len_of_data(pos, f_ctx->end, vaddr->ltype);
	const loff_t off_in_bk = off_in_data(pos, vaddr->ltype);
	int err;

	fni_incref(flref->parent_fni);
	err = filc_zero_data_leaf_range(f_ctx, vaddr, off_in_bk, len);
	fni_decref(flref->parent_fni);
	return err;
}

static int filc_discard_partial_by(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_ref *flref)
{
	int err;

	err = filc_unshare_leaf_by(f_ctx, flref);
	if (err) {
		return err;
	}
	err = filc_zero_data_leaf_range_by(f_ctx, flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_discard_data_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_fileaf_ref *flref)
{
	int err;

	fni_incref(flref->parent_fni);
	err = filc_discard_data_leaf(f_ctx, &flref->vaddr);
	fni_decref(flref->parent_fni);
	return err;
}

static int filc_discard_entire_by(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_fileaf_ref *flref)
{
	int err;

	err = filc_discard_data_leaf_by(f_ctx, flref);
	if (err) {
		return err;
	}
	if (flref->head1) {
		filc_reset_head1_leaf_by(f_ctx, flref);
	} else if (flref->head2) {
		filc_reset_head2_leaf_by(f_ctx, flref);
	} else if (flref->tree && flref->parent_fni) {
		filc_clear_subtree_mappings_by(f_ctx, flref);
	}
	return 0;
}

static int filc_discard_via_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                         const struct silofs_fileaf_ref *flref)
{
	return silofs_mark_unwritten_at(f_ctx->task, &flref->vaddr);
}

static bool filc_zero_range_mode(const struct silofs_file_ctx *f_ctx)
{
	return fl_mode_zero_range(f_ctx->fl_mode);
}

static int filc_discard_data_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_fileaf_ref *flref)
{
	int err;
	int ret = 0;

	if (!flref->has_data) {
		return 0;
	}
	err = filc_detect_shared_by(f_ctx, flref);
	if (err) {
		return err;
	}
	if (flref->partial) {
		ret = filc_discard_partial_by(f_ctx, flref);
	} else if (!flref->shared && filc_zero_range_mode(f_ctx)) {
		ret = filc_discard_via_unwritten_by(f_ctx, flref);
	} else {
		ret = filc_discard_entire_by(f_ctx, flref);
	}
	return ret;
}

static int filc_discard_by_tree(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree(f_ctx, &flref);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = filc_discard_data_by(f_ctx, &flref);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, &flref);
		err = filc_discard_data_by(f_ctx, &flref);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, &flref);
		err = filc_discard_data_by(f_ctx, &flref);
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

	err = filc_discard_by_heads(f_ctx);
	if (err) {
		return err;
	}
	err = filc_discard_by_tree(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_discard_unused_meta(struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->beg == 0) ? filc_drop_data_and_meta(f_ctx) : 0;
}

static int
filc_resolve_heads_end(const struct silofs_file_ctx *f_ctx, loff_t *out_end)
{
	struct silofs_vaddr vaddr;
	size_t slot;

	*out_end = 0;
	if (!filc_ftype1_mode(f_ctx)) {
		goto out;
	}
	slot = SILOFS_FILE_HEAD2_NLEAF;
	while (slot-- > 0) {
		filc_head2_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			*out_end = off_head2_end_of(slot);
			goto out;
		}
	}
	slot = SILOFS_FILE_HEAD1_NLEAF;
	while (slot-- > 0) {
		filc_head1_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			*out_end = off_head1_end_of(slot);
			goto out;
		}
	}
out:
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
	loff_t lend = 0;
	loff_t tend = 0;
	int err;

	err = filc_resolve_heads_end(f_ctx, &lend);
	if (err) {
		return err;
	}
	err = filc_resolve_tree_end(f_ctx, &tend);
	if (err) {
		return err;
	}
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

int silofs_do_truncate(struct silofs_task *task, struct silofs_inode_info *ii,
                       loff_t off)
{
	const loff_t isp = ii_span(ii);
	const size_t len = (off < isp) ? off_ulen(off, isp) : 0;
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
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
                                struct silofs_fileaf_ref *out_flref)
{
	int err;

	flref_reset(out_flref);
	err = filc_seek_data_by_heads(f_ctx, out_flref);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = filc_seek_by_tree(f_ctx, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_lseek_data(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	loff_t isz;
	int err;

	isz = ii_size(f_ctx->ii);
	err = filc_lseek_data_leaf(f_ctx, &flref);
	if (err == -SILOFS_ENOENT) {
		f_ctx->off = isz;
		return -SILOFS_ENXIO;
	}
	if (err) {
		return err;
	}
	f_ctx->off = off_clamp(flref.file_pos, f_ctx->off, isz);
	return 0;
}

static int filc_lseek_hole_noleaf(struct silofs_file_ctx *f_ctx,
                                  struct silofs_fileaf_ref *flref)
{
	int err;

	err = filc_seek_hole_by_heads(f_ctx, flref);
	if (err == -SILOFS_ENOENT) {
		err = filc_seek_by_tree(f_ctx, flref);
	}
	return err;
}

static int filc_lseek_hole(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref = { .file_pos = -1 };
	loff_t isz;
	int err;

	isz = ii_size(f_ctx->ii);
	err = filc_lseek_hole_noleaf(f_ctx, &flref);
	if (err == 0) {
		f_ctx->off = off_clamp(flref.file_pos, f_ctx->off, isz);
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

int silofs_do_lseek(struct silofs_task *task, struct silofs_inode_info *ii,
                    loff_t off, int whence, loff_t *out_off)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
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

#define FALLOC_FL_MODE_MASK                                \
	(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE | \
	 FALLOC_FL_ZERO_RANGE | FALLOC_FL_INSERT_RANGE |   \
	 FALLOC_FL_UNSHARE_RANGE)

/*
 * TODO-0012: Proper hanfling for FALLOC_FL_KEEP_SIZE beyond file size
 *
 * See 'man 2 fallocate' for semantics details of FALLOC_FL_KEEP_SIZE
 * beyond end-of-file.
 */
/*
 * TODO-0055: Have FALLOC_FL_ALLOCATE_RANGE
 */
/*
 * TODO-0055: Implement FALLOC_FL_UNSHARE_RANGE
 *
 * Allow sub-file ranges to become unshared.
 */
static int filc_check_fl_mode(const struct silofs_file_ctx *f_ctx)
{
	const int mode = f_ctx->fl_mode;
	int mask;

	/* require exclusive modes */
	mask = FALLOC_FL_MODE_MASK;
	switch (mode & mask) {
	case FALLOC_FL_UNSHARE_RANGE:
	case FALLOC_FL_ZERO_RANGE:
		break;
	case FALLOC_FL_PUNCH_HOLE:
		if (!(mode & FALLOC_FL_KEEP_SIZE)) {
			return -SILOFS_EOPNOTSUPP;
		}
		break;
	case FALLOC_FL_COLLAPSE_RANGE:
	case FALLOC_FL_INSERT_RANGE:
		if (mode & FALLOC_FL_KEEP_SIZE) {
			return -SILOFS_EOPNOTSUPP;
		}
		break;
	default:
		if (mode & mask) {
			return -SILOFS_EOPNOTSUPP;
		}
		break;
	}
	/* punch hole and zero range are mutually exclusive */
	mask = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;
	if ((mode & mask) == mask) {
		return -SILOFS_EOPNOTSUPP;
	}
	/* currently known modes */
	mask = FALLOC_FL_MODE_MASK | FALLOC_FL_KEEP_SIZE;
	if (mode & ~mask) {
		return -SILOFS_EOPNOTSUPP;
	}
	/* currently supported modes */
	mask = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
	       FALLOC_FL_ZERO_RANGE;
	if (mode & ~mask) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int filc_create_bind_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni)
{
	struct silofs_fileaf_ref flref;
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fni, &flref);
	if (flref.has_data) {
		return filc_require_mut_by(f_ctx, &flref);
	}
	err = filc_create_data_leaf(f_ctx, SILOFS_LTYPE_DATABK, &flref.vaddr);
	if (err) {
		return err;
	}
	fni_bind_child(parent_fni, f_ctx->off, &flref.vaddr);
	fni_dirtify(parent_fni, f_ctx->ii);
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
		err = filc_require_tree_node(f_ctx, fni, &fni);
		if (err) {
			return err;
		}
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_reserve_by_tree(struct silofs_file_ctx *f_ctx)
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

static int filc_fallocate_reserve_by_tree(struct silofs_file_ctx *f_ctx)
{
	int err = 0;

	while (!err && filc_has_more_io(f_ctx)) {
		err = filc_reserve_by_tree(f_ctx);
	}
	return err;
}

static int filc_fallocate_reserve_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		err = filc_require_head1_leaf(f_ctx, &flref);
		if (err) {
			return err;
		}
		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		err = filc_require_head2_leaf(f_ctx, &flref);
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

	err = filc_fallocate_reserve_by_heads(f_ctx);
	if (err) {
		return err;
	}
	err = filc_fallocate_reserve_by_tree(f_ctx);
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
	filc_update_post_io(f_ctx, true);
	return 0;
}

int silofs_do_fallocate(struct silofs_task *task, struct silofs_inode_info *ii,
                        int mode, loff_t off, loff_t len)
{
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
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
	len = len_of_data(f_ctx->off, end, vaddr->ltype);
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
                             const struct silofs_fileaf_ref *flref)
{
	bool ok = true;

	if (flref->has_data) {
		ok = filc_emit_fiemap_ext(f_ctx, &flref->vaddr);
		if (!ok) {
			f_ctx->fm_stop = true;
		}
	}
	return ok;
}

static int filc_fiemap_by_tree_leaves(struct silofs_file_ctx *f_ctx,
                                      struct silofs_finode_info *parent_fni)
{
	struct silofs_fileaf_ref flref;

	fni_incref(parent_fni);
	while (filc_has_more_io(f_ctx)) {
		filc_resolve_tree_leaf(f_ctx, parent_fni, &flref);
		if (!filc_emit_fiemap(f_ctx, &flref)) {
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

static int filc_fiemap_by_tree(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref flref;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree(f_ctx, &flref);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = filc_fiemap_by_tree_leaves(f_ctx, flref.parent_fni);
		if (err) {
			return err;
		}
		/* TODO: need to skip large holes */
	}
	return 0;
}

static int filc_fiemap_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_fileaf_ref fm;

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

	err = filc_fiemap_by_heads(f_ctx);
	if (err) {
		return err;
	}
	err = filc_fiemap_by_tree(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_check_fm_flags(const struct silofs_file_ctx *f_ctx)
{
	const int fm_allowed = FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR |
	                       FIEMAP_FLAG_CACHE;

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

static loff_t
ii_off_end(const struct silofs_inode_info *ii, loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t isz = ii_size(ii);

	return off_min(end, isz);
}

int silofs_do_fiemap(struct silofs_task *task, struct silofs_inode_info *ii,
                     struct fiemap *fm)
{
	const loff_t off = (loff_t)fm->fm_start;
	const size_t len = (size_t)fm->fm_length;
	struct silofs_file_ctx f_ctx = {
		.task = task,
		.fsenv = task->t_fsenv,
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

static int filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_finode_info *parent_fni,
                                       struct silofs_fileaf_ref *out_flref);

static int filc_resolve_fpos_by_heads(struct silofs_file_ctx *f_ctx,
                                      struct silofs_fileaf_ref *out_flref)
{
	int err = 0;

	if (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_flref);
	} else if (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_flref);
	} else {
		err = -SILOFS_ENOENT;
	}
	return err;
}

static int filc_resolve_fpos_recursive_at(
	struct silofs_file_ctx *f_ctx, struct silofs_finode_info *parent_fni,
	size_t slot, struct silofs_fileaf_ref *out_flref)
{
	struct silofs_vaddr vaddr;
	struct silofs_finode_info *fni = NULL;
	int err;

	fni_resolve_child_by_slot(parent_fni, slot, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return -SILOFS_ENOENT;
	}
	err = filc_stage_tree_node(f_ctx, &vaddr, &fni);
	if (err) {
		return err;
	}
	err = filc_resolve_fpos_recursive(f_ctx, fni, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int
filc_do_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_finode_info *parent_fni,
                               struct silofs_fileaf_ref *out_flref)
{
	const loff_t off = f_ctx->off;
	size_t slot;

	if (!fni_isinrange(parent_fni, off)) {
		return -SILOFS_ENOENT;
	}
	slot = fni_child_slot_of(parent_fni, off);
	if (fni_isbottom(parent_fni)) {
		filc_resolve_child_at(f_ctx, parent_fni, off, slot, out_flref);
		return 0;
	}
	return filc_resolve_fpos_recursive_at(f_ctx, parent_fni, slot,
	                                      out_flref);
}

static int filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_finode_info *parent_fni,
                                       struct silofs_fileaf_ref *out_flref)
{
	int ret;

	fni_incref(parent_fni);
	ret = filc_do_resolve_fpos_recursive(f_ctx, parent_fni, out_flref);
	fni_decref(parent_fni);
	return ret;
}

static int filc_resolve_fpos_by_tree(struct silofs_file_ctx *f_ctx,
                                     struct silofs_fileaf_ref *out_flref)
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
	err = filc_resolve_fpos_recursive(f_ctx, root_fni, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_resolve_fpos(struct silofs_file_ctx *f_ctx,
                             struct silofs_fileaf_ref *out_flref)
{
	int err;

	flref_reset(out_flref);
	err = filc_resolve_fpos_by_heads(f_ctx, out_flref);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = filc_resolve_fpos_by_tree(f_ctx, out_flref);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	flref_noent(out_flref, f_ctx->ii, f_ctx->off, f_ctx->end);
	return -SILOFS_ENOENT;
}

static size_t filc_copy_length_of(const struct silofs_file_ctx *f_ctx)
{
	const size_t len_to_end = off_ulen(f_ctx->off, f_ctx->end);
	const size_t len_to_next = filc_distance_to_next(f_ctx);

	return min(len_to_end, len_to_next);
}

static size_t filc_copy_range_length(const struct silofs_file_ctx *f_ctx_src,
                                     const struct silofs_file_ctx *f_ctx_dst)
{
	const size_t len_src = filc_copy_length_of(f_ctx_src);
	const size_t len_dst = filc_copy_length_of(f_ctx_dst);

	return min(len_src, len_dst);
}

static int filc_clear_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_fileaf_ref *flref,
                                   struct silofs_fileaf_info *fli)
{
	int err;

	if (!flref->unwritten) {
		return 0;
	}
	err = filc_clear_unwritten_of(f_ctx, fli);
	if (err) {
		return err;
	}
	flref->unwritten = false;
	return 0;
}

static int
filc_copy_data_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                       struct silofs_fileaf_ref *flref_src,
                       const struct silofs_file_ctx *f_ctx_dst,
                       struct silofs_fileaf_ref *flref_dst, size_t len)
{
	struct silofs_iovec iov_src = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_iovec iov_dst = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_fileaf_info *fli_src = NULL;
	struct silofs_fileaf_info *fli_dst = NULL;
	int err;
	bool all;

	err = filc_stage_fileaf(f_ctx_src, &flref_src->vaddr, &fli_src);
	if (err) {
		goto out;
	}
	fli_incref(fli_src);

	err = filc_stage_fileaf(f_ctx_dst, &flref_dst->vaddr, &fli_dst);
	if (err) {
		goto out;
	}
	fli_incref(fli_dst);

	all = (len == flref_src->vaddr.len);
	filc_iovec_by_fileaf(f_ctx_src, fli_src, all, &iov_src);

	all = (len == flref_dst->vaddr.len);
	filc_iovec_by_fileaf(f_ctx_dst, fli_dst, all, &iov_dst);

	err = silofs_iovec_copy_mem(&iov_src, &iov_dst, len);
	if (err) {
		goto out;
	}
	fli_dirtify(fli_dst, f_ctx_dst->ii);

	err = filc_clear_unwritten_by(f_ctx_dst, flref_dst, fli_dst);
	if (err) {
		goto out;
	}
out:
	fli_decref(fli_dst);
	fli_decref(fli_src);
	return err;
}

static int filc_copy_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                             struct silofs_fileaf_ref *flref_src,
                             const struct silofs_file_ctx *f_ctx_dst,
                             struct silofs_fileaf_ref *flref_dst, size_t len)
{
	int err;

	err = filc_pre_write_leaf(f_ctx_dst, flref_dst, len);
	if (err) {
		return err;
	}
	err = filc_pre_write_leaf(f_ctx_src, flref_src, len);
	if (err) {
		return err;
	}
	err = filc_copy_data_leaf_by(f_ctx_src, flref_src, f_ctx_dst,
	                             flref_dst, len);
	if (err) {
		return err;
	}
	return 0;
}

static void filc_rebind_child_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_fileaf_ref *flref,
                                 const struct silofs_vaddr *vaddr)
{
	fni_bind_child(flref->parent_fni, f_ctx->off, vaddr);
	fni_dirtify(flref->parent_fni, f_ctx->ii);
	vaddr_assign(&flref->vaddr, vaddr);
}

static int filc_unshare_leaf_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_fileaf_ref *flref)
{
	struct silofs_fileaf_ref flref_new;
	size_t len;
	int err;

	silofs_assert(flref->has_data);
	if (!flref->shared || !flref->tree) {
		return 0;
	}
	flref_setup(&flref_new, f_ctx->ii, flref->parent_fni, &flref->vaddr,
	            flref->file_pos, f_ctx->end);
	err = filc_claim_data_space(f_ctx, flref->vaddr.ltype,
	                            &flref_new.vaddr);
	if (err) {
		return err;
	}
	len = flref->vaddr.len;
	err = filc_copy_data_leaf_by(f_ctx, flref, f_ctx, &flref_new, len);
	if (err) {
		filc_reclaim_data_space(f_ctx, &flref_new.vaddr);
		return err;
	}
	err = filc_reclaim_data_space(f_ctx, &flref->vaddr);
	if (err) {
		return err;
	}
	filc_rebind_child_by(f_ctx, flref, &flref_new.vaddr);
	return 0;
}

static int filc_require_tree_and_leaf(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_fileaf_ref *out_flref)
{
	struct silofs_finode_info *parent_fni = NULL;
	int err;

	err = filc_require_tree(f_ctx, &parent_fni);
	if (err) {
		return err;
	}
	err = filc_require_tree_leaf(f_ctx, parent_fni, out_flref);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_require_ftype1_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fileaf_ref *out_flref)
{
	int ret;

	if (off_is_head1(f_ctx->off)) {
		ret = filc_require_head1_leaf(f_ctx, out_flref);
	} else if (off_is_head2(f_ctx->off)) {
		ret = filc_require_head2_leaf(f_ctx, out_flref);
	} else {
		ret = filc_require_tree_and_leaf(f_ctx, out_flref);
	}
	return ret;
}

static int filc_require_ftype2_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_fileaf_ref *out_flref)
{
	return filc_require_tree_and_leaf(f_ctx, out_flref);
}

static int filc_require_leaf(const struct silofs_file_ctx *f_ctx,
                             struct silofs_fileaf_ref *out_flref)
{
	int ret;

	if (filc_ftype1_mode(f_ctx)) {
		ret = filc_require_ftype1_leaf(f_ctx, out_flref);
	} else {
		ret = filc_require_ftype2_leaf(f_ctx, out_flref);
	}
	return ret;
}

static int filc_share_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                              const struct silofs_fileaf_ref *flref_src,
                              const struct silofs_file_ctx *f_ctx_dst,
                              struct silofs_fileaf_ref *flref_dst)
{
	int err;

	err = filc_share_data_space(f_ctx_src, &flref_src->vaddr);
	if (err) {
		return err;
	}
	filc_rebind_child_by(f_ctx_dst, flref_dst, &flref_src->vaddr);
	filc_update_iblocks(f_ctx_dst, &flref_dst->vaddr, 1);
	return 0;
}

static bool filc_test_ismutable_by(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_fileaf_ref *flref)
{
	return laddr_isnull(&flref->laddr) ||
	       silofs_sbi_ismutable_laddr(f_ctx->sbi, &flref->laddr);
}

static bool
filc_test_may_share_leaf_by(const struct silofs_file_ctx *f_ctx,
                            const struct silofs_fileaf_ref *flref, bool is_src)
{
	if (is_src && !flref->has_data) {
		return false;
	}
	if (!flref->tree) {
		return false;
	}
	if (flref->partial) {
		return false;
	}
	return filc_test_ismutable_by(f_ctx, flref);
}

static int filc_resolve_laddr_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_fileaf_ref *flref)
{
	struct silofs_llink llink;
	int err;

	if (vaddr_isnull(&flref->vaddr)) {
		return 0;
	}
	err = silofs_resolve_llink_of(f_ctx->task, &flref->vaddr,
	                              f_ctx->stg_mode, &llink);
	if (err) {
		return err;
	}
	laddr_assign(&flref->laddr, &llink.laddr);
	return 0;
}

static int filc_require_tree_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_fileaf_ref *out_flref)
{
	struct silofs_finode_info *fni = NULL;
	int err;

	err = filc_require_tree(f_ctx, &fni);
	if (err) {
		return err;
	}
	filc_resolve_tree_leaf(f_ctx, fni, out_flref);
	return 0;
}

static int
filc_copy_range_at_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                           struct silofs_fileaf_ref *flref_src,
                           const struct silofs_file_ctx *f_ctx_dst,
                           struct silofs_fileaf_ref *flref_dst, size_t len)
{
	int err;

	if (!flref_src->has_data && flref_dst->has_data) {
		err = filc_require_mut_by(f_ctx_dst, flref_dst);
		if (err) {
			return err;
		}
		err = filc_unshare_leaf_by(f_ctx_dst, flref_dst);
		if (err) {
			return err;
		}
		err = filc_discard_data_by(f_ctx_dst, flref_dst);
		if (err) {
			return err;
		}
	} else if (flref_src->has_data && !flref_dst->has_data) {
		err = filc_resolve_laddr_by(f_ctx_src, flref_src);
		if (err) {
			return err;
		}
		if (filc_test_may_share_leaf_by(f_ctx_src, flref_src, 1) &&
		    filc_test_may_share_leaf_by(f_ctx_dst, flref_dst, 0)) {
			err = filc_require_tree_by(f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
			err = filc_share_leaf_by(f_ctx_src, flref_src,
			                         f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
		} else {
			err = filc_require_leaf(f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
			err = filc_require_mut_by(f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
			err = filc_copy_leaf_by(f_ctx_src, flref_src,
			                        f_ctx_dst, flref_dst, len);
			if (err) {
				return err;
			}
		}
	} else if (flref_src->has_data && flref_dst->has_data) {
		err = filc_require_mut_by(f_ctx_dst, flref_dst);
		if (err) {
			return err;
		}
		err = filc_resolve_laddr_by(f_ctx_src, flref_src);
		if (err) {
			return err;
		}
		err = filc_resolve_laddr_by(f_ctx_dst, flref_dst);
		if (err) {
			return err;
		}
		if (filc_test_may_share_leaf_by(f_ctx_src, flref_src, 1) &&
		    filc_test_may_share_leaf_by(f_ctx_dst, flref_dst, 0)) {
			err = filc_discard_data_by(f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
			err = filc_share_leaf_by(f_ctx_src, flref_src,
			                         f_ctx_dst, flref_dst);
			if (err) {
				return err;
			}
		} else {
			err = filc_copy_leaf_by(f_ctx_src, flref_src,
			                        f_ctx_dst, flref_dst, len);
			if (err) {
				return err;
			}
		}
	} /* else: !flref_src->has_data && !flref_dst->has_data (no-op) */
	return 0;
}

static int filc_copy_range_iter(struct silofs_file_ctx *f_ctx_src,
                                struct silofs_file_ctx *f_ctx_dst)
{
	struct silofs_fileaf_ref flref_src;
	struct silofs_fileaf_ref flref_dst;
	size_t len;
	int err;

	while (filc_has_more_io(f_ctx_src) && filc_has_more_io(f_ctx_dst)) {
		err = filc_resolve_fpos(f_ctx_src, &flref_src);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		err = filc_resolve_fpos(f_ctx_dst, &flref_dst);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		len = filc_copy_range_length(f_ctx_src, f_ctx_dst);
		if (!len) {
			break;
		}
		err = filc_copy_range_at_leaf_by(f_ctx_src, &flref_src,
		                                 f_ctx_dst, &flref_dst, len);
		if (err) {
			return err;
		}
		filc_advance_by_nbytes(f_ctx_src, len);
		filc_advance_by_nbytes(f_ctx_dst, len);
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
	if ((f_ctx_src->ii == f_ctx_dst->ii) && ((off_dst + len) > off_src) &&
	    (off_dst < (off_src + len))) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int
filc_lseek_data_pos(const struct silofs_file_ctx *f_ctx, loff_t *out_off)
{
	struct silofs_fileaf_ref flref = {
		.file_pos = -1,
	};
	struct silofs_file_ctx f_ctx_alt = {
		.task = f_ctx->task,
		.fsenv = f_ctx->fsenv,
		.sbi = f_ctx->sbi,
		.ii = f_ctx->ii,
		.len = 0,
		.beg = f_ctx->beg,
		.off = f_ctx->off,
		.end = f_ctx->end,
		.op_mask = OP_LSEEK,
		.whence = SEEK_DATA,
		.stg_mode = SILOFS_STG_CUR,
	};
	int err;

	err = filc_lseek_data_leaf(&f_ctx_alt, &flref);
	if (!err) {
		*out_off = flref.file_pos;
	} else if (err == -SILOFS_ENOENT) {
		*out_off = SILOFS_FILE_SIZE_MAX;
		err = 0;
	}
	return err;
}

static int filc_set_copy_range_start(struct silofs_file_ctx *f_ctx_src,
                                     struct silofs_file_ctx *f_ctx_dst)
{
	loff_t off_data_src = 0;
	loff_t off_data_dst = 0;
	ssize_t skip_src = 0;
	ssize_t skip_dst = 0;
	ssize_t skip = 0;
	int err;

	err = filc_lseek_data_pos(f_ctx_src, &off_data_src);
	if (err) {
		return err;
	}
	err = filc_lseek_data_pos(f_ctx_dst, &off_data_dst);
	if (err) {
		return err;
	}
	if (f_ctx_src->off < off_data_src) {
		skip_src = off_len(f_ctx_src->off, off_data_src);
	}
	if (f_ctx_dst->off < off_data_dst) {
		skip_dst = off_len(f_ctx_dst->off, off_data_dst);
	}
	skip = silofs_min_i64(skip_src, skip_dst);
	filc_advance_by_nbytes2(f_ctx_src, f_ctx_dst, skip);
	return 0;
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

static int filc_copy_range(struct silofs_file_ctx *f_ctx_src,
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
	err = filc_set_copy_range_start(f_ctx_src, f_ctx_dst);
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

int silofs_do_copy_file_range(struct silofs_task *task,
                              struct silofs_inode_info *ii_in,
                              struct silofs_inode_info *ii_out, loff_t off_in,
                              loff_t off_out, size_t len, int flags,
                              size_t *out_ncp)
{
	struct silofs_file_ctx f_ctx_src = {
		.task = task,
		.fsenv = task->t_fsenv,
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
		.fsenv = task->t_fsenv,
		.sbi = task_sbi(task),
		.ii = ii_out,
		.len = len,
		.beg = off_out,
		.off = off_out,
		.end = off_end(off_out, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
		.with_backref = 0,
		.stg_mode = SILOFS_STG_COW,
	};
	int ret;

	filc_incref(&f_ctx_src);
	filc_incref(&f_ctx_dst);
	ret = filc_copy_range(&f_ctx_src, &f_ctx_dst, out_ncp);
	filc_decref(&f_ctx_dst);
	filc_decref(&f_ctx_src);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_setup_reg(struct silofs_inode_info *ii)
{
	struct silofs_inode_file *infl = ii_infl_of(ii);

	infl_setup(infl);
	ii_dirtify(ii);
}

int silofs_verify_ftree_node(const struct silofs_ftree_node *ftn)
{
	loff_t spbh;
	const loff_t span = ftn_span(ftn);
	const size_t height = ftn_height(ftn);
	enum silofs_ltype child_ltype;
	enum silofs_ltype expect_ltype;
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
	child_ltype = ftn_child_ltype(ftn);
	ftn_child_ltype_by_height(ftn, height, &expect_ltype);
	if (child_ltype != expect_ltype) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (ftn_isbottom(ftn) && !silofs_ltype_isdatabk(child_ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}
