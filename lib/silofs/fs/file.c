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
#include <linux/falloc.h>
#include <linux/fiemap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/vfs.h>
#include <silofs/fs.h>

#define SILOFS_USE_FILE_PRIVATE 1
#include "filep.h"

/* Local functions forward declarations. */
static int filc_unshare_flnode_by(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_flnode_ref *fdr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static enum silofs_file_type ii_ftype(const struct silofs_inode_info *ii)
{
	const enum silofs_inodef iflags = silofs_ii_flags(ii);
	enum silofs_file_type ftype;

	silofs_assert(silofs_ii_isreg(ii));

	if (iflags & SILOFS_INODEF_FTYPE2) {
		ftype = SILOFS_FILE_TYPE2;
	} else {
		ftype = SILOFS_FILE_TYPE1;
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

static off_t off_in_data(off_t off, enum silofs_ltype ltype)
{
	const ssize_t len = silofs_ltype_ssize(ltype);

	return likely(len > 0) ? off % len : off;
}

static size_t len_to_next(off_t off, enum silofs_ltype ltype)
{
	const ssize_t len = silofs_ltype_ssize(ltype);

	return off_ulen(off, off_next(off, len));
}

static size_t len_of_data(off_t off, off_t end, enum silofs_ltype ltype)
{
	const ssize_t len = silofs_ltype_ssize(ltype);
	const off_t nxt   = off_next(off, len);

	return (nxt < end) ? off_ulen(off, nxt) : off_ulen(off, end);
}

static bool off_is_partial(off_t off, off_t end, enum silofs_ltype ltype)
{
	const ssize_t len = silofs_ltype_ssize(ltype);
	const off_t beg   = likely(len > 0) ? silofs_off_align(off, len) : off;
	const ssize_t io_len = silofs_off_len(off, end);

	return (off != beg) || (io_len < len);
}

static bool off_is_partial_head1(off_t off, off_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATA1K);
}

static bool off_is_partial_head2(off_t off, off_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATA4K);
}

static bool off_is_partial_leaf(off_t off, off_t end)
{
	return off_is_partial(off, end, SILOFS_LTYPE_DATA64K);
}

static off_t off_end(off_t off, size_t len)
{
	return silofs_off_end(off, len);
}

static off_t off_head1_end_of(size_t slot)
{
	constexpr size_t leaf_size = SILOFS_FILE_HEAD1_LEAF_SIZE;

	return off_end(0, (slot + 1) * leaf_size);
}

static off_t off_head1_max(void)
{
	return off_head1_end_of(SILOFS_FILE_HEAD1_NLEAF - 1);
}

static off_t off_head2_end_of(size_t slot)
{
	constexpr size_t leaf_size = (size_t)SILOFS_FILE_HEAD2_LEAF_SIZE;

	return off_end(off_head1_max(), (slot + 1) * leaf_size);
}

static off_t off_head2_max(void)
{
	return off_head2_end_of(SILOFS_FILE_HEAD2_NLEAF - 1);
}

static bool off_is_head1(off_t off)
{
	return off_within(off, 0, off_head1_max());
}

static bool off_is_head2(off_t off)
{
	return off_within(off, off_head1_max(), off_head2_max());
}

static size_t off_to_head1_slot(off_t off)
{
	constexpr size_t slot_size = SILOFS_FILE_HEAD1_LEAF_SIZE;
	size_t slot;

	silofs_assert_lt(off, 4 * SILOFS_KILO);
	slot = (size_t)off / slot_size;

	silofs_assert_lt(slot, SILOFS_FILE_HEAD1_NLEAF);
	return slot;
}

static size_t off_to_head2_slot(off_t off)
{
	constexpr size_t slot_size = (size_t)SILOFS_FILE_HEAD2_LEAF_SIZE;

	return (size_t)(off - off_head1_max()) / slot_size;
}

static size_t off_to_leaf_slot(off_t off)
{
	constexpr size_t slot_size = SILOFS_FILE_TREE_LEAF_SIZE;
	constexpr size_t nchilds   = SILOFS_FTREE_NODE_NCHILDS;

	return ((size_t)off / slot_size) % nchilds;
}

static size_t off_to_tree_height(off_t off)
{
	constexpr uint64_t leaf_size = SILOFS_FILE_TREE_LEAF_SIZE;
	constexpr size_t height_max  = SILOFS_FILE_HEIGHT_MAX;
	constexpr int shift          = SILOFS_FILE_MAP_SHIFT;
	uint64_t uoff, height;

	/* TODO: count bits */
	uoff   = (uint64_t)off;
	height = 2;
	if (uoff > leaf_size) {
		uint64_t xpos = (uoff / leaf_size) >> shift;

		while ((xpos > 0) && (height < height_max)) {
			height += 1;
			xpos = (xpos >> shift);
		}
	}
	silofs_assert_le(height, height_max);
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
	constexpr int fl_mask = FALLOC_FL_KEEP_SIZE;

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
fli_setdirty(struct silofs_flnode_info *fli, struct silofs_inode_info *ii)
{
	silofs_lni_setdirty(&fli->fln_lni, ii);
}

static void fli_incref(struct silofs_flnode_info *fli)
{
	if (likely(fli != nullptr)) {
		silofs_lni_incref(&fli->fln_lni);
	}
}

static void fli_decref(struct silofs_flnode_info *fli)
{
	if (likely(fli != nullptr)) {
		silofs_lni_decref(&fli->fln_lni);
	}
}

static const struct silofs_laddr *
fli_laddr(const struct silofs_flnode_info *fli)
{
	silofs_assume_not_null(fli);
	return silofs_lni_laddr(&fli->fln_lni);
}

static enum silofs_ltype fli_ltype(const struct silofs_flnode_info *fli)
{
	return silofs_lni_ltype(&fli->fln_lni);
}

static size_t fli_data_len(const struct silofs_flnode_info *fli)
{
	return silofs_ltype_size(fli_ltype(fli));
}

static void *fli_data_at(const struct silofs_flnode_info *fli, off_t pos)
{
	size_t dat_size               = 0;
	uint8_t *dat_base             = nullptr;
	const enum silofs_ltype ltype = fli_ltype(fli);

	if (ltype == SILOFS_LTYPE_DATA1K) {
		dat_size = sizeof(fli->fln.dn1->dat);
		dat_base = fli->fln.dn1->dat;
	} else if (ltype == SILOFS_LTYPE_DATA4K) {
		dat_size = sizeof(fli->fln.dn4->dat);
		dat_base = fli->fln.dn4->dat;
	} else if (ltype == SILOFS_LTYPE_DATA64K) {
		dat_size = sizeof(fli->fln.dn64->dat);
		dat_base = fli->fln.dn64->dat;
	}

	if ((dat_base == nullptr) || (pos >= (ssize_t)dat_size) || (pos < 0)) {
		silofs_panic("illegal reference for file-data: "
		             "ltype=%d pos=%ld",
		             (int)ltype, pos);
	}
	return &dat_base[pos];
}

static off_t fli_off_within(const struct silofs_flnode_info *fli, off_t off)
{
	return off_in_data(off, fli_ltype(fli));
}

static size_t
fli_len_within(const struct silofs_flnode_info *fli, off_t off, off_t end)
{
	return len_of_data(off, end, fli_ltype(fli));
}

static void fli_pre_io(struct silofs_flnode_info *fli, bool asyncwr_mode)
{
	fli_incref(fli);
	if (asyncwr_mode) {
		silofs_atomic_sqc_add(&fli->fln_lni.ln_asyncwr, 1);
	}
}

static void fli_post_io(struct silofs_flnode_info *fli, bool asyncwr_mode)
{
	fli_decref(fli);
	if (asyncwr_mode) {
		silofs_atomic_sqc_sub(&fli->fln_lni.ln_asyncwr, 1);
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

static off_t ftn_beg(const struct silofs_ftree_node *ftn)
{
	return silofs_off_to_cpu(ftn->fn_beg);
}

static void ftn_set_beg(struct silofs_ftree_node *ftn, off_t beg)
{
	ftn->fn_beg = silofs_cpu_to_off(beg);
}

static off_t ftn_end(const struct silofs_ftree_node *ftn)
{
	return silofs_off_to_cpu(ftn->fn_end);
}

static void ftn_set_end(struct silofs_ftree_node *ftn, off_t end)
{
	ftn->fn_end = silofs_cpu_to_off(end);
}

static size_t ftn_nchilds_max(const struct silofs_ftree_node *ftn)
{
	return ARRAY_SIZE(ftn->fn_child);
}

static size_t ftn_span(const struct silofs_ftree_node *ftn)
{
	return off_ulen(ftn_beg(ftn), ftn_end(ftn));
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
	return ftn_span(ftn) / ftn_nchilds_max(ftn);
}

static size_t
ftn_slot_by_file_pos(const struct silofs_ftree_node *ftn, off_t file_pos)
{
	uint64_t span, roff, slot, nslots;
	constexpr int shift = SILOFS_FILE_MAP_SHIFT;

	/*
	  Basic math:
	    slot / nslots == roff / span ==> slot == (roff * nslots) / span

	  However, need to do a right-shift to avoid integer-overflow.
	*/
	nslots = ftn_nchilds_max(ftn);
	span   = ftn_span(ftn) >> shift;
	roff   = (uint64_t)off_diff(ftn_beg(ftn), file_pos) >> shift;
	slot   = ((roff * nslots) / span);
	return slot;
}

static off_t ftn_child(const struct silofs_ftree_node *ftn, size_t slot)
{
	off_t off = 0;

	silofs_laddr56_xtoh(&ftn->fn_child[slot], &off);
	return off;
}

static void
ftn_set_child(struct silofs_ftree_node *ftn, size_t slot, off_t off)
{
	silofs_laddr56_htox(&ftn->fn_child[slot], off);
}

static void ftn_reset_child(struct silofs_ftree_node *ftn, size_t slot)
{
	ftn_set_child(ftn, slot, SILOFS_OFF_NULL);
}

static bool ftn_has_child_at(const struct silofs_ftree_node *ftn, size_t slot)
{
	const off_t voff = ftn_child(ftn, slot);

	return !silofs_off_isnull(voff);
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

static bool ftn_isinrange(const struct silofs_ftree_node *ftn, off_t pos)
{
	return off_within(pos, ftn_beg(ftn), ftn_end(ftn));
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
		*out_child_ltype = SILOFS_LTYPE_DATA64K;
	} else {
		*out_child_ltype = SILOFS_LTYPE_FTNODE;
	}
	silofs_unused(ftn);
}

static off_t
ftn_span_by_height(const struct silofs_ftree_node *ftn, size_t height)
{
	constexpr uint64_t bk_size    = SILOFS_FILE_TREE_LEAF_SIZE;
	constexpr uint64_t fm_shift   = SILOFS_FILE_MAP_SHIFT;
	constexpr uint64_t height_max = SILOFS_FILE_HEIGHT_MAX;
	off_t span;

	if (likely((height > 1) && (height <= height_max))) {
		span = (off_t)(bk_size << ((height - 1) * fm_shift));
	} else {
		span = LONG_MAX; /* make clang-scan happy */
	}
	silofs_unused(ftn);
	return span;
}

static void ftn_calc_range(const struct silofs_ftree_node *ftn, off_t off,
                           size_t height, off_t *beg, off_t *end)
{
	const off_t span = ftn_span_by_height(ftn, height);

	*beg = silofs_off_align(off, span);
	*end = silofs_off_min(*beg + span, SILOFS_FILE_SIZE_MAX + 1);
}

static off_t ftn_file_pos(const struct silofs_ftree_node *ftn, size_t slot)
{
	off_t next_off;
	const size_t nbps = ftn_nbytes_per_slot(ftn);

	next_off = off_end(ftn_beg(ftn), slot * nbps);
	return off_align_to_lbk(next_off);
}

static off_t
ftn_next_file_pos(const struct silofs_ftree_node *ftn, size_t slot)
{
	off_t file_pos;
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

static void ftn_init(struct silofs_ftree_node *ftn, ino_t ino, off_t beg,
                     off_t end, size_t height, enum silofs_ltype child_ltype)
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

static void
ftn_init_by(struct silofs_ftree_node *ftn, ino_t ino, off_t off, size_t height)
{
	off_t beg, end;
	enum silofs_ltype child_ltype;

	ftn_child_ltype_by_height(ftn, height, &child_ltype);
	ftn_calc_range(ftn, off, height, &beg, &end);
	ftn_init(ftn, ino, beg, end, height, child_ltype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_file *filin_of(const struct silofs_inode *inode)
{
	const struct silofs_inode_file *filin = &inode->i_ta.f;

	return silofs_unconst(filin);
}

static void filin_validate_vslots(const struct silofs_inode_file *filin)
{
	/* Slot-0: root; Slots [1..4]: 1K data; Slots [5..20]: 4K. */
	STATICASSERT_GT(ARRAY_SIZE(filin->f_slots),
	                1 + SILOFS_FILE_HEAD1_NLEAF + SILOFS_FILE_HEAD2_NLEAF);

	STATICASSERT_EQ(SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF,
	                SILOFS_FILE_HEAD2_LEAF_SIZE);
	STATICASSERT_EQ((SILOFS_FILE_HEAD1_LEAF_SIZE *
	                 SILOFS_FILE_HEAD1_NLEAF) +
	                        (SILOFS_FILE_HEAD2_LEAF_SIZE *
	                         SILOFS_FILE_HEAD2_NLEAF),
	                SILOFS_FILE_TREE_LEAF_SIZE);
}

static size_t filin_vslot_of_root(const struct silofs_inode_file *filin)
{
	filin_validate_vslots(filin);
	return 0;
}

static size_t
filin_vslot_of_head1(const struct silofs_inode_file *filin, size_t head1_slot)
{
	filin_validate_vslots(filin);
	silofs_assert_lt(head1_slot, SILOFS_FILE_HEAD1_NLEAF);

	/* use modulo to make clang-scan happy */
	return (1 + head1_slot) % ARRAY_SIZE(filin->f_slots);
}

static size_t
filin_vslot_of_head2(const struct silofs_inode_file *filin, size_t head2_slot)
{
	filin_validate_vslots(filin);
	silofs_assert_lt(head2_slot, SILOFS_FILE_HEAD2_NLEAF);

	/* use modulo to make clang-scan happy */
	return (1 + SILOFS_FILE_HEAD1_NLEAF + head2_slot) %
	       ARRAY_SIZE(filin->f_slots);
}

static void filin_head1_leaf(const struct silofs_inode_file *filin,
                             size_t head1_slot, struct silofs_laddr *out_laddr)
{
	const size_t slot = filin_vslot_of_head1(filin, head1_slot);

	silofs_laddr64_xtoh(&filin->f_slots[slot], out_laddr);
}

static void
filin_set_head1_leaf(struct silofs_inode_file *filin, size_t head1_slot,
                     const struct silofs_laddr *laddr)
{
	const size_t slot = filin_vslot_of_head1(filin, head1_slot);

	silofs_laddr64_htox(&filin->f_slots[slot], laddr);
}

static void filin_head2_leaf(const struct silofs_inode_file *filin,
                             size_t head2_slot, struct silofs_laddr *out_laddr)
{
	const size_t slot = filin_vslot_of_head2(filin, head2_slot);

	silofs_laddr64_xtoh(&filin->f_slots[slot], out_laddr);
}

static void
filin_set_head2_leaf(struct silofs_inode_file *filin, size_t head2_slot,
                     const struct silofs_laddr *laddr)
{
	const size_t slot = filin_vslot_of_head2(filin, head2_slot);

	silofs_laddr64_htox(&filin->f_slots[slot], laddr);
}

static void filin_tree_root(const struct silofs_inode_file *filin,
                            struct silofs_laddr *out_laddr)
{
	const size_t slot = filin_vslot_of_root(filin);

	silofs_laddr64_xtoh(&filin->f_slots[slot], out_laddr);
}

static void filin_set_tree_root(struct silofs_inode_file *filin,
                                const struct silofs_laddr *laddr)
{
	const size_t slot = filin_vslot_of_root(filin);

	silofs_laddr64_htox(&filin->f_slots[slot], laddr);
}

static void filin_setup(struct silofs_inode_file *filin)
{
	const struct silofs_laddr *laddr = laddr_none();

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD1_NLEAF; ++slot) {
		filin_set_head1_leaf(filin, slot, laddr);
	}
	for (size_t slot = 0; slot < SILOFS_FILE_HEAD2_NLEAF; ++slot) {
		filin_set_head2_leaf(filin, slot, laddr);
	}
	filin_set_tree_root(filin, laddr);
}

static struct silofs_inode_file *
ii_filin_of(const struct silofs_inode_info *ii)
{
	return filin_of(ii->inode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
fti_setdirty(struct silofs_ftnode_info *fti, struct silofs_inode_info *ii)
{
	silofs_lni_setdirty(&fti->ftn_lni, ii);
}

static void fti_incref(struct silofs_ftnode_info *fti)
{
	if (likely(fti != nullptr)) {
		silofs_lni_incref(&fti->ftn_lni);
	}
}

static void fti_decref(struct silofs_ftnode_info *fti)
{
	if (likely(fti != nullptr)) {
		silofs_lni_decref(&fti->ftn_lni);
	}
}

static const struct silofs_laddr *
fti_laddr(const struct silofs_ftnode_info *fti)
{
	return silofs_lni_laddr(&fti->ftn_lni);
}

static void fti_get_laddr(const struct silofs_ftnode_info *fti,
                          struct silofs_laddr *out_laddr)
{
	silofs_laddr_assign(out_laddr, fti_laddr(fti));
}

static bool fti_isinrange(const struct silofs_ftnode_info *fti, off_t file_pos)
{
	return ftn_isinrange(fti->ftn, file_pos);
}

static bool fti_isbottom(const struct silofs_ftnode_info *fti)
{
	return ftn_isbottom(fti->ftn);
}

static size_t fti_height(const struct silofs_ftnode_info *fti)
{
	return ftn_height(fti->ftn);
}

static size_t fti_nchilds_max(const struct silofs_ftnode_info *fti)
{
	return ftn_nchilds_max(fti->ftn);
}

static size_t
fti_child_slot_of(const struct silofs_ftnode_info *fti, off_t off)
{
	return ftn_slot_by_file_pos(fti->ftn, off);
}

static void fti_assign_child_at(struct silofs_ftnode_info *fti, size_t slot,
                                const struct silofs_laddr *laddr)
{
	struct silofs_ftree_node *ftn = fti->ftn;
	const off_t voff              = laddr->off;

	if (!ftn_has_child_at(ftn, slot)) {
		if (!silofs_off_isnull(voff)) {
			ftn_set_child(ftn, slot, voff);
			ftn_inc_nactive_childs(ftn);
		} else {
			ftn_reset_child(ftn, slot);
		}
	} else {
		if (!silofs_off_isnull(voff)) {
			ftn_set_child(ftn, slot, voff);
		} else {
			ftn_reset_child(ftn, slot);
			ftn_dec_nactive_childs(ftn);
		}
	}
}

static void fti_assign_child_by_pos(struct silofs_ftnode_info *fti, off_t pos,
                                    const struct silofs_laddr *laddr)
{
	size_t child_slot;

	child_slot = fti_child_slot_of(fti, pos);
	fti_assign_child_at(fti, child_slot, laddr);
}

static void fti_bind_child(struct silofs_ftnode_info *parent_fti,
                           off_t file_pos, const struct silofs_laddr *laddr)
{
	if (parent_fti != nullptr) {
		silofs_assert(!laddr_isnull(laddr));
		fti_assign_child_by_pos(parent_fti, file_pos, laddr);
	}
}

static void fti_bind_finode(struct silofs_ftnode_info *parent_fti,
                            off_t file_pos, struct silofs_ftnode_info *fti)
{
	fti_bind_child(parent_fti, file_pos, fti_laddr(fti));
	ftn_inc_refcnt(fti->ftn);
}

static void
fti_clear_subtree_mappings(struct silofs_ftnode_info *fti, size_t slot)
{
	if (ftn_has_child_at(fti->ftn, slot)) {
		ftn_reset_child(fti->ftn, slot);
		ftn_dec_nactive_childs(fti->ftn);
	}
}

static void
fti_setup(struct silofs_ftnode_info *fti, const struct silofs_inode_info *ii,
          off_t off, size_t height)
{
	ftn_init_by(fti->ftn, ii->i_ino, off, height);
}

static void fti_resolve_child_by_slot(const struct silofs_ftnode_info *fti,
                                      size_t slot, struct silofs_laddr *laddr)
{
	const struct silofs_ftree_node *ftn = fti->ftn;
	const off_t off                     = ftn_child(ftn, slot);

	silofs_laddr_setup(laddr, ftn_child_ltype(ftn), off);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void filc_incref(const struct silofs_file_ctx *f_ctx)
{
	silofs_ii_incref(f_ctx->ii);
}

static void filc_decref(const struct silofs_file_ctx *f_ctx)
{
	silofs_ii_decref(f_ctx->ii);
}

static void *filc_nilbk(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_lblock *nilbk = f_ctx->task->corefs->nilbk;

	return nilbk->u.bk;
}

static void filc_iovec_by_flnode(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_info *fli, bool all,
                                 struct silofs_iovec *out_iov)
{
	off_t off_within;
	size_t len;

	if (all) {
		off_within = 0;
		len        = fli_data_len(fli);
	} else {
		off_within = fli_off_within(fli, f_ctx->off);
		len        = fli_len_within(fli, f_ctx->off, f_ctx->end);
	}

	silofs_iovec_reset(out_iov);
	out_iov->iov.iov_base = fli_data_at(fli, off_within);
	out_iov->iov.iov_len  = len;
	out_iov->iov_backref  = f_ctx->with_backref ? fli : nullptr;
}

static void filc_iovec_by_nilbk(const struct silofs_file_ctx *f_ctx,
                                const enum silofs_ltype ltype,
                                struct silofs_iovec *out_iov)
{
	silofs_iovec_reset(out_iov);
	out_iov->iov.iov_base = filc_nilbk(f_ctx);
	out_iov->iov.iov_len  = len_of_data(f_ctx->off, f_ctx->end, ltype);
	out_iov->iov_off      = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_require_mut_laddr(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr)
{
	/* XXX FIXME FIXME FIXME */
	silofs_unused(f_ctx);
	silofs_unused(laddr);
	return 0;
}

static size_t filc_io_length(const struct silofs_file_ctx *f_ctx)
{
	return off_ulen(f_ctx->beg, f_ctx->off);
}

static bool filc_has_more_io(const struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->off < f_ctx->end) && !f_ctx->fm_stop &&
	       !f_ctx->task->interrupted;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void fdr_reset(struct silofs_flnode_ref *fdr)
{
	silofs_memzero(fdr, sizeof(*fdr));
	silofs_laddr_reset(&fdr->laddr);
}

static void
fdr_setup(struct silofs_flnode_ref *fdr, struct silofs_inode_info *ii,
          struct silofs_ftnode_info *parent_fti,
          const struct silofs_laddr *laddr, off_t file_pos, off_t io_end)
{
	const bool ftype2 = ii_isftype2(ii);

	fdr_reset(fdr);
	silofs_laddr_assign(&fdr->laddr, laddr);
	fdr->ii         = ii;
	fdr->parent_fti = parent_fti;
	fdr->slot_idx   = UINT_MAX;
	fdr->file_pos   = file_pos;
	fdr->has_data   = !laddr_isnull(laddr);
	fdr->has_hole   = !fdr->has_data;
	fdr->shared     = false;
	fdr->unwritten  = true;

	if (!ftype2 && off_is_head1(file_pos)) {
		fdr->head1     = true;
		fdr->slot_idx  = off_to_head1_slot(file_pos);
		fdr->partial   = off_is_partial_head1(file_pos, io_end);
		fdr->leaf_size = (size_t)SILOFS_FILE_HEAD1_LEAF_SIZE;
	} else if (!ftype2 && off_is_head2(file_pos)) {
		fdr->head2     = true;
		fdr->slot_idx  = off_to_head2_slot(file_pos);
		fdr->partial   = off_is_partial_head2(file_pos, io_end);
		fdr->leaf_size = (size_t)SILOFS_FILE_HEAD2_LEAF_SIZE;
	} else {
		fdr->tree      = true;
		fdr->slot_idx  = off_to_leaf_slot(file_pos);
		fdr->partial   = off_is_partial_leaf(file_pos, io_end);
		fdr->leaf_size = (size_t)SILOFS_FILE_TREE_LEAF_SIZE;
	}
}

static void
fdr_setup1(struct silofs_flnode_ref *fdr, struct silofs_inode_info *ii,
           const struct silofs_laddr *laddr, off_t file_pos, off_t io_end)
{
	fdr_setup(fdr, ii, nullptr, laddr, file_pos, io_end);
}

static void
fdr_setup2(struct silofs_flnode_ref *fdr, struct silofs_inode_info *ii,
           const struct silofs_laddr *laddr, off_t file_pos, off_t io_end)
{
	fdr_setup(fdr, ii, nullptr, laddr, file_pos, io_end);
}

static void
fdr_noent(struct silofs_flnode_ref *fdr, struct silofs_inode_info *ii,
          off_t file_pos, off_t io_end)
{
	fdr_setup(fdr, ii, nullptr, laddr_none(), file_pos, io_end);
}

static void fdr_update_partial(struct silofs_flnode_ref *fdr, size_t len)
{
	if (len > 0) {
		fdr->partial = (len < fdr->leaf_size);
	}
}

static enum silofs_ltype fdr_ltype(const struct silofs_flnode_ref *fdr)
{
	return fdr->laddr.ltype;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool filc_ftype1_mode(const struct silofs_file_ctx *f_ctx)
{
	return ii_isftype1(f_ctx->ii);
}

static void
filc_resolve_child_at(const struct silofs_file_ctx *f_ctx,
                      struct silofs_ftnode_info *fti, off_t file_pos,
                      size_t slot, struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;

	fti_resolve_child_by_slot(fti, slot, &laddr);
	fdr_setup(out_fdr, f_ctx->ii, fti, &laddr, file_pos, f_ctx->end);
}

static void filc_resolve_child(const struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *fti, off_t file_pos,
                               struct silofs_flnode_ref *out_fdr)
{
	size_t slot;

	if (fti != nullptr) {
		slot = fti_child_slot_of(fti, file_pos);
		filc_resolve_child_at(f_ctx, fti, file_pos, slot, out_fdr);
	} else {
		fdr_setup(out_fdr, f_ctx->ii, nullptr, laddr_none(), file_pos,
		          f_ctx->end);
	}
}

static void filc_resolve_child_of(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info *fti,
                                  struct silofs_laddr *out_laddr)
{
	size_t slot;

	silofs_laddr_reset(out_laddr);
	if (fti != nullptr) {
		slot = fti_child_slot_of(fti, f_ctx->off);
		fti_resolve_child_by_slot(fti, slot, out_laddr);
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
                               size_t slot, struct silofs_laddr *out_laddr)
{
	const struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_head1_leaf(filin, slot, out_laddr);
}

static void filc_resolve_head1_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	const size_t slot = filc_head1_leaf_slot_of(f_ctx);

	filc_head1_leaf_at(f_ctx, slot, &laddr);
	fdr_setup(out_fdr, f_ctx->ii, nullptr, &laddr, f_ctx->off, f_ctx->end);
}

static void
filc_set_head1_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot,
                       const struct silofs_laddr *laddr)
{
	struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_set_head1_leaf(filin, slot, laddr);
}

static size_t filc_head2_leaf_slot_of(const struct silofs_file_ctx *f_ctx)
{
	return off_to_head2_slot(f_ctx->off);
}

static void filc_head2_leaf_at(const struct silofs_file_ctx *f_ctx,
                               size_t slot, struct silofs_laddr *out_laddr)
{
	const struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_head2_leaf(filin, slot, out_laddr);
}

static void filc_resolve_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	const size_t slot = filc_head2_leaf_slot_of(f_ctx);

	filc_head2_leaf_at(f_ctx, slot, &laddr);
	fdr_setup2(out_fdr, f_ctx->ii, &laddr, f_ctx->off, f_ctx->end);
}

static void
filc_set_head2_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot,
                       const struct silofs_laddr *laddr)
{
	struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_set_head2_leaf(filin, slot, laddr);
}

static void filc_tree_root_of(const struct silofs_file_ctx *f_ctx,
                              struct silofs_laddr *out_laddr)
{
	const struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_tree_root(filin, out_laddr);
}

static bool filc_has_tree_root(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_laddr laddr;

	filc_tree_root_of(f_ctx, &laddr);
	return (laddr.ltype == SILOFS_LTYPE_FTNODE);
}

static void filc_set_tree_root_at(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr)
{
	struct silofs_inode_file *filin = ii_filin_of(f_ctx->ii);

	filin_set_tree_root(filin, laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filc_curr_data_ltype(const struct silofs_file_ctx *f_ctx,
                                 enum silofs_ltype *out_ltype)
{
	*out_ltype = SILOFS_LTYPE_DATA64K;
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

static void filc_advance_to(struct silofs_file_ctx *f_ctx, off_t off)
{
	f_ctx->off = off_clamp(f_ctx->off, off, f_ctx->end);
}

static void filc_advance_by_nbytes(struct silofs_file_ctx *f_ctx, size_t len)
{
	silofs_assert_gt(len, 0);
	filc_advance_to(f_ctx, silofs_off_end(f_ctx->off, len));
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
                          const struct silofs_ftnode_info *fti, size_t slt)
{
	filc_advance_to(f_ctx, ftn_file_pos(fti->ftn, slt));
}

static void
filc_advance_to_next_tree_slot(struct silofs_file_ctx *f_ctx,
                               const struct silofs_ftnode_info *fti,
                               size_t slt)
{
	filc_advance_to(f_ctx, ftn_next_file_pos(fti->ftn, slt));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_check_reg(const struct silofs_file_ctx *f_ctx)
{
	enum silofs_file_type ftype;

	if (silofs_ii_isdir(f_ctx->ii)) {
		return -SILOFS_EISDIR;
	}
	if (!silofs_ii_isreg(f_ctx->ii)) {
		return -SILOFS_EINVAL;
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
	const off_t isz  = silofs_ii_size(f_ctx->ii);
	const off_t pos  = f_ctx->off;
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
	const off_t off       = f_ctx->beg;
	const ssize_t slen    = (off_t)f_ctx->len;
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
	const off_t end       = f_ctx->end;
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
	return_if_err(err);

	err = filc_check_isopen(f_ctx);
	if (f_ctx->op != SILOFS_FILE_OP_TRUNC) {
		return_if_err(err);
	}

	err = filc_check_io_range(f_ctx);
	return_if_err(err);

	if ((f_ctx->op == SILOFS_FILE_OP_WRITE) && f_ctx->o_flags) {
		if (!(f_ctx->o_flags & (O_RDWR | O_WRONLY))) {
			return -SILOFS_EPERM;
		}
	}
	if ((f_ctx->op == SILOFS_FILE_OP_WRITE) ||
	    (f_ctx->op == SILOFS_FILE_OP_FALLOC)) {
		err = filc_check_io_end(f_ctx);
		return_if_err(err);
	}
	if ((f_ctx->op == SILOFS_FILE_OP_READ) ||
	    (f_ctx->op == SILOFS_FILE_OP_WRITE)) {
		if (f_ctx->len > SILOFS_IO_SIZE_MAX) {
			return -SILOFS_EINVAL;
		}
		if (!f_ctx->rwi_ctx) {
			return -SILOFS_EINVAL;
		}
	}
	if (f_ctx->op == SILOFS_FILE_OP_LSEEK) {
		err = filc_check_seek_pos(f_ctx);
		return_if_err(err);
	}
	if (f_ctx->op == SILOFS_FILE_OP_COPY_RANGE) {
		if (f_ctx->cp_flags != 0) {
			return -SILOFS_EINVAL;
		}
		if (!off_lbk_aligned(f_ctx->beg) &&
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
                                    struct silofs_ftnode_info *parent_fti,
                                    struct silofs_flnode_ref *out_fdr);

static bool filc_ismapping_boundaries(const struct silofs_file_ctx *f_ctx)
{
	const off_t mapping_size =
		(SILOFS_FILE_TREE_LEAF_SIZE * SILOFS_FTREE_NODE_NCHILDS);

	return ((f_ctx->off % mapping_size) == 0);
}

static void filc_setup_iattr(const struct silofs_file_ctx *f_ctx,
                             struct silofs_iattr *iattr)
{
	silofs_make_iattr_of(f_ctx->ii, iattr);
}

static void filc_update_iattr(const struct silofs_file_ctx *f_ctx,
                              const struct silofs_iattr *iattr)
{
	silofs_update_iattrs_of(f_ctx->task, f_ctx->ii, iattr);
}

static void filc_update_post_io(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_iattr iattr = {
		.ia_flags = SILOFS_IATTR_NONE,
		.ia_size  = -1,
	};
	const off_t isz  = silofs_ii_size(f_ctx->ii);
	const off_t isp  = silofs_ii_span(f_ctx->ii);
	const size_t len = filc_io_length(f_ctx);

	filc_setup_iattr(f_ctx, &iattr);

	switch (f_ctx->op) {
	case SILOFS_FILE_OP_READ:
		iattr.ia_flags |= SILOFS_IATTR_ATIME | SILOFS_IATTR_LAZY;
		break;
	case SILOFS_FILE_OP_WRITE:
	case SILOFS_FILE_OP_COPY_RANGE:
		iattr.ia_flags |= SILOFS_IATTR_SIZE | SILOFS_IATTR_SPAN;
		iattr.ia_size = off_max(f_ctx->off, isz);
		iattr.ia_span = off_max(f_ctx->off, isp);
		if (len > 0) {
			iattr.ia_flags |= SILOFS_IATTR_MCTIME;
			if (f_ctx->kill_suidgid) {
				iattr.ia_flags |= SILOFS_IATTR_KILL_SUIDGID;
			}
		}
		break;
	case SILOFS_FILE_OP_FALLOC:
		iattr.ia_flags |= SILOFS_IATTR_MCTIME | SILOFS_IATTR_SPAN;
		iattr.ia_span = off_max(f_ctx->end, isp);
		if (!fl_mode_keep_size(f_ctx->fl_mode)) {
			iattr.ia_flags |= SILOFS_IATTR_SIZE;
			iattr.ia_size = off_max(f_ctx->end, isz);
		}
		break;
	case SILOFS_FILE_OP_TRUNC:
		iattr.ia_flags |= SILOFS_IATTR_SIZE | SILOFS_IATTR_SPAN;
		iattr.ia_size = f_ctx->beg;
		iattr.ia_span = f_ctx->beg;
		if (isz != f_ctx->beg) {
			iattr.ia_flags |= SILOFS_IATTR_MCTIME;
			if (f_ctx->kill_suidgid) {
				iattr.ia_flags |= SILOFS_IATTR_KILL_SUIDGID;
			}
		}
		break;
	case SILOFS_FILE_OP_LSEEK:
	case SILOFS_FILE_OP_FIEMAP:
	case SILOFS_FILE_OP_DROP:
	case SILOFS_FILE_OP_NONE:
	default:
		break;
	}

	filc_update_iattr(f_ctx, &iattr);
}

static int
filc_test_unwritten_at(const struct silofs_file_ctx *f_ctx,
                       const struct silofs_laddr *laddr, bool *out_unwritten)
{
	int ret = 0;

	*out_unwritten = true;
	if (!laddr_isnull(laddr)) {
		ret = silofs_test_unwritten_flnode(f_ctx->task, laddr,
		                                   f_ctx->ii, out_unwritten);
	}
	return ret;
}

static int filc_update_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_ref *fdr)
{
	return filc_test_unwritten_at(f_ctx, &fdr->laddr, &fdr->unwritten);
}

static int
filc_update_pre_write_leaf_by(const struct silofs_file_ctx *f_ctx,
                              struct silofs_flnode_ref *fdr, size_t len)
{
	fdr_update_partial(fdr, len);
	return filc_update_unwritten_by(f_ctx, fdr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_recheck_flnode(const struct silofs_file_ctx *f_ctx,
                               struct silofs_flnode_info *fli)
{
	if (silofs_lni_need_recheck(&fli->fln_lni)) {
		/* no-op for file-leaf */
		silofs_lni_set_rechecked(&fli->fln_lni);
	}
	silofs_unused(f_ctx);
	return 0;
}

static int filc_stage_flnode(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_laddr *laddr,
                             struct silofs_flnode_info **out_fli)
{
	int err;

	err = silofs_stage_flnode(f_ctx->task, laddr, f_ctx->ii,
	                          f_ctx->stg_mode, out_fli);
	return_if_err(err);

	err = filc_recheck_flnode(f_ctx, *out_fli);
	return_if_err(err);

	return 0;
}

static void filc_setdirty_flnode(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_info *fli)
{
	fli_setdirty(fli, f_ctx->ii);
}

static void filc_zero_flnode_sub(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_info *fli,
                                 off_t off_in_dn, size_t len)
{
	void *dat = fli_data_at(fli, off_in_dn);

	silofs_memzero(dat, len);
	filc_setdirty_flnode(f_ctx, fli);
}

static int filc_zero_flnode_range(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr,
                                  off_t off_in_dn, size_t len)
{
	struct silofs_flnode_info *fli = nullptr;
	int err;

	err = filc_stage_flnode(f_ctx, laddr, &fli);
	return_if_err(err);

	filc_zero_flnode_sub(f_ctx, fli, off_in_dn, len);
	return 0;
}

static int filc_zero_data_leaf_at(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr)
{
	return filc_zero_flnode_range(f_ctx, laddr, 0, laddr_len(laddr));
}

static int filc_do_recheck_ftnode(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_ftnode_info *fti)
{
	const ino_t fnode_ino = ftn_ino(fti->ftn);
	const ino_t owner_ino = f_ctx->ii->i_ino;
	const size_t height   = ftn_height(fti->ftn);

	if (fnode_ino != owner_ino) {
		log_err("bad finode ino: fnode_ino=%lu owner_ino=%lu",
		        fnode_ino, owner_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	if ((height < 2) || (height > 16)) {
		log_err("illegal height: height=%lu ino=%lu", height,
		        owner_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int filc_recheck_ftnode(const struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *fti)
{
	int err;

	if (silofs_lni_need_recheck(&fti->ftn_lni)) {
		err = filc_do_recheck_ftnode(f_ctx, fti);
		return_if_err(err);

		silofs_lni_set_rechecked(&fti->ftn_lni);
	}
	return 0;
}

static int filc_check_sub_laddr(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_laddr *laddr)
{
	silofs_unused(f_ctx);
	return laddr_isnull(laddr) ? -SILOFS_ENOENT : 0;
}

static int filc_stage_ftnode(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_laddr *laddr,
                             struct silofs_ftnode_info **out_fti)
{
	int err;

	err = filc_check_sub_laddr(f_ctx, laddr);
	return_if_err(err);

	err = silofs_stage_ftnode(f_ctx->task, laddr, f_ctx->ii,
	                          f_ctx->stg_mode, out_fti);
	return_if_err(err);

	err = filc_recheck_ftnode(f_ctx, *out_fti);
	return_if_err(err);

	return 0;
}

static int filc_stage_root_ftnode(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info **out_fti)
{
	struct silofs_laddr root_laddr;

	filc_tree_root_of(f_ctx, &root_laddr);
	return filc_stage_ftnode(f_ctx, &root_laddr, out_fti);
}

static size_t filc_iter_start_slot(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_ftnode_info *parent_fti)
{
	return fti_child_slot_of(parent_fti, f_ctx->off);
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
                                    struct silofs_ftnode_info *parent_fti,
                                    struct silofs_flnode_ref *out_fdr)
{
	size_t start_slot, nslots_max;
	const bool seek_hole = filc_is_seek_hole(f_ctx);

	start_slot = filc_iter_start_slot(f_ctx, parent_fti);
	nslots_max = fti_nchilds_max(parent_fti);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		filc_advance_to_tree_slot(f_ctx, parent_fti, slot);
		if (!filc_has_more_io(f_ctx)) {
			break;
		}
		filc_resolve_child_at(f_ctx, parent_fti, f_ctx->off, slot,
		                      out_fdr);
		if (seek_hole == out_fdr->has_hole) {
			return 0;
		}
	}
	return -SILOFS_ENOENT;
}

static int
filc_seek_tree_recursive_at(struct silofs_file_ctx *f_ctx,
                            struct silofs_ftnode_info *parent_fti, size_t slot,
                            struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	struct silofs_ftnode_info *fti = nullptr;
	int err;

	fti_resolve_child_by_slot(parent_fti, slot, &laddr);

	err = filc_check_sub_laddr(f_ctx, &laddr);
	return_if_err(err);

	err = filc_stage_ftnode(f_ctx, &laddr, &fti);
	return_if_err(err);

	err = filc_seek_tree_recursive(f_ctx, fti, out_fdr);
	return_if_err(err);

	return 0;
}

static int filc_do_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_ftnode_info *parent_fti,
                                       struct silofs_flnode_ref *out_fdr)
{
	const size_t nslots_max = fti_nchilds_max(parent_fti);
	size_t start_slot;
	int ret;

	if (!fti_isinrange(parent_fti, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}
	if (fti_isbottom(parent_fti)) {
		return filc_seek_tree_at_leaves(f_ctx, parent_fti, out_fdr);
	}

	ret = filc_is_seek_hole(f_ctx) ? 0 : -SILOFS_ENOENT;

	start_slot = fti_child_slot_of(parent_fti, f_ctx->off);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		ret = filc_seek_tree_recursive_at(f_ctx, parent_fti, slot,
		                                  out_fdr);
		if (ret != -SILOFS_ENOENT) {
			break;
		}
		filc_advance_to_next_tree_slot(f_ctx, parent_fti, slot);
	}
	return ret;
}

static int filc_seek_tree_recursive(struct silofs_file_ctx *f_ctx,
                                    struct silofs_ftnode_info *parent_fti,
                                    struct silofs_flnode_ref *out_fdr)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_seek_tree_recursive(f_ctx, parent_fti, out_fdr);
	fti_decref(parent_fti);
	return ret;
}

static int filc_check_tree_root(const struct silofs_file_ctx *f_ctx)
{
	return !filc_has_tree_root(f_ctx) ? -SILOFS_ENOENT : 0;
}

static int filc_seek_by_tree(struct silofs_file_ctx *f_ctx,
                             struct silofs_flnode_ref *out_fdr)
{
	struct silofs_ftnode_info *root_fti = nullptr;
	int err;

	err = filc_check_tree_root(f_ctx);
	return_if_err(err);

	err = filc_stage_root_ftnode(f_ctx, &root_fti);
	return_if_err(err);

	err = filc_seek_tree_recursive(f_ctx, root_fti, out_fdr);
	return_if_err(err);

	return 0;
}

static int filc_seek_data_by_head1(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fdr);
		if (out_fdr->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_seek_data_by_head2(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fdr);
		if (out_fdr->has_data) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_seek_data_by_heads(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	int err;

	err = filc_seek_data_by_head1(f_ctx, out_fdr);
	return_if_not_err(err);

	err = filc_seek_data_by_head2(f_ctx, out_fdr);
	return_if_not_err(err);

	return -SILOFS_ENOENT;
}

static int filc_seek_hole_by_head1(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	while (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fdr);
		if (out_fdr->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_seek_hole_by_head2(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	while (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fdr);
		if (out_fdr->has_hole) {
			return 0;
		}
		filc_advance_to_next(f_ctx);
	}
	return -SILOFS_ENOENT;
}

static int filc_seek_hole_by_heads(struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	int err;

	err = filc_seek_hole_by_head1(f_ctx, out_fdr);
	return_if_not_err(err);

	err = filc_seek_hole_by_head2(f_ctx, out_fdr);
	return_if_not_err(err);

	return -SILOFS_ENOENT;
}

static void filc_resolve_iovec(const struct silofs_file_ctx *f_ctx,
                               struct silofs_flnode_info *fli,
                               struct silofs_iovec *out_iov)
{
	enum silofs_ltype ltype;

	if (fli != nullptr) {
		filc_iovec_by_flnode(f_ctx, fli, false, out_iov);
	} else {
		filc_curr_data_ltype(f_ctx, &ltype);
		filc_iovec_by_nilbk(f_ctx, ltype, out_iov);
	}
}

static void iovref_pre(const struct silofs_iovec *iov, bool asyncwr_mode)
{
	struct silofs_flnode_info *fli = iov->iov_backref;

	if (fli != nullptr) {
		fli_pre_io(fli, asyncwr_mode);
	}
}

static void iovref_post(const struct silofs_iovec *iov, bool asyncwr_mode)
{
	struct silofs_flnode_info *fli = iov->iov_backref;

	if (fli != nullptr) {
		fli_post_io(fli, asyncwr_mode);
	}
}

static bool filc_asyncwr_mode(const struct silofs_file_ctx *f_ctx)
{
	bool asyncwr = false;

	if (f_ctx->op == SILOFS_FILE_OP_WRITE) {
		const enum silofs_flags ctl_flags =
			f_ctx->task->corefs->fsroot->ctl_flags;

		asyncwr = (ctl_flags & SILOFS_F_ASYNCWR) > 0;
	}
	return asyncwr;
}

static int filc_call_rw_actor(const struct silofs_file_ctx *f_ctx,
                              struct silofs_flnode_info *fli, size_t *out_len)
{
	struct silofs_iovec iovec = {
		.iov.iov_base = nullptr,
		.iov.iov_len  = 0,
		.iov_backref  = nullptr,
		.iov_off      = -1,
		.iov_fd       = -1,
	};
	const bool asyncwr = filc_asyncwr_mode(f_ctx);
	int err;

	filc_resolve_iovec(f_ctx, fli, &iovec);
	iovref_pre(&iovec, asyncwr);
	err = f_ctx->rwi_ctx->actor(f_ctx->rwi_ctx, &iovec);

	*out_len = iovec.iov.iov_len;
	if (err || !f_ctx->with_backref) {
		iovref_post(&iovec, asyncwr);
	}
	return err;
}

static int
filc_export_data_by_flnode(const struct silofs_file_ctx *f_ctx,
                           struct silofs_flnode_info *fli, size_t *out_sz)
{
	return filc_call_rw_actor(f_ctx, fli, out_sz);
}

static int
filc_export_data_by_curr(struct silofs_file_ctx *f_ctx, size_t *out_sz)
{
	return filc_call_rw_actor(f_ctx, nullptr, out_sz);
}

static int
filc_import_data_by_flnode(const struct silofs_file_ctx *f_ctx,
                           struct silofs_flnode_info *fli, size_t *out_sz)
{
	int err;

	err = filc_call_rw_actor(f_ctx, fli, out_sz);
	return_if_err(err);

	filc_setdirty_flnode(f_ctx, fli);
	return 0;
}

static void filc_child_of_current_pos(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_ftnode_info *parent_fti,
                                      struct silofs_flnode_ref *out_fdr)
{
	filc_resolve_child(f_ctx, parent_fti, f_ctx->off, out_fdr);
}

static void filc_resolve_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_ftnode_info *parent_fti,
                                   struct silofs_flnode_ref *out_fdr)
{
	filc_child_of_current_pos(f_ctx, parent_fti, out_fdr);
}

static void filc_resolve_tree_node(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_ftnode_info *parent_fti,
                                   struct silofs_laddr *out_laddr)
{
	filc_resolve_child_of(f_ctx, parent_fti, out_laddr);
}

static int filc_do_stage_by_tree_from(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_ftnode_info *root_fti,
                                      struct silofs_ftnode_info **out_fti)
{
	struct silofs_ftnode_info *fti = root_fti;
	struct silofs_laddr laddr;
	size_t height;
	int err;

	height = fti_height(fti);
	while (height--) {
		if (fti_isbottom(fti)) {
			*out_fti = fti;
			return 0;
		}
		filc_resolve_tree_node(f_ctx, fti, &laddr);

		err = filc_stage_ftnode(f_ctx, &laddr, &fti);
		return_if_err(err);
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_stage_by_tree_from(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_ftnode_info *root_fti,
                                   struct silofs_ftnode_info **out_fti)
{
	int ret;

	fti_incref(root_fti);
	ret = filc_do_stage_by_tree_from(f_ctx, root_fti, out_fti);
	fti_decref(root_fti);
	return ret;
}

static int filc_stage_by_tree(const struct silofs_file_ctx *f_ctx,
                              struct silofs_ftnode_info **out_fti)
{
	struct silofs_ftnode_info *root_fti = nullptr;
	int err;

	*out_fti = nullptr;
	if (!filc_has_tree_root(f_ctx)) {
		return -SILOFS_ENOENT;
	}

	err = filc_stage_root_ftnode(f_ctx, &root_fti);
	return_if_err(err);

	if (!fti_isinrange(root_fti, f_ctx->off)) {
		return -SILOFS_ENOENT;
	}

	err = filc_stage_by_tree_from(f_ctx, root_fti, out_fti);
	return_if_err(err);

	return 0;
}

static int filc_read_flnode_by_copy(struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_info *fli, size_t *sz)
{
	int err;

	fli_incref(fli);
	err = filc_export_data_by_flnode(f_ctx, fli, sz);
	fli_decref(fli);
	return err;
}

static int
filc_read_leaf_as_zeros(struct silofs_file_ctx *f_ctx, size_t *out_sz)
{
	return filc_export_data_by_curr(f_ctx, out_sz);
}

static int filc_stage_flnode_by(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_flnode_ref *fdr,
                                struct silofs_flnode_info **out_fli)
{
	int ret = -SILOFS_ENOENT;

	*out_fli = nullptr;
	if (fdr->has_data) {
		ret = filc_stage_flnode(f_ctx, &fdr->laddr, out_fli);
	}
	return ret;
}

static int filc_read_from_leaf(struct silofs_file_ctx *f_ctx,
                               struct silofs_flnode_ref *fdr, size_t *out_len)
{
	struct silofs_flnode_info *fli = nullptr;
	int err;

	err = filc_update_unwritten_by(f_ctx, fdr);
	return_if_err(err);

	if (fdr->unwritten) {
		err = filc_read_leaf_as_zeros(f_ctx, out_len);
		return_if_err(err);
	} else {
		err = filc_stage_flnode_by(f_ctx, fdr, &fli);
		return_if_err_and_not(err, -SILOFS_ENOENT);

		err = filc_read_flnode_by_copy(f_ctx, fli, out_len);
		return_if_err(err);
	}
	return 0;
}

static int filc_do_read_from_tree_leaves(struct silofs_file_ctx *f_ctx,
                                         struct silofs_ftnode_info *parent_fti)
{
	int err;

	while (filc_has_more_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};
		size_t len                   = 0;

		filc_resolve_tree_leaf(f_ctx, parent_fti, &fdr);

		err = filc_read_from_leaf(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);
		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int filc_read_from_tree_leaves(struct silofs_file_ctx *f_ctx,
                                      struct silofs_ftnode_info *parent_fti)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_read_from_tree_leaves(f_ctx, parent_fti);
	fti_decref(parent_fti);

	return ret;
}

static int filc_read_by_tree(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_more_io(f_ctx)) {
		struct silofs_ftnode_info *parent_fti = nullptr;

		err = filc_stage_by_tree(f_ctx, &parent_fti);
		return_if_err_and_not(err, -SILOFS_ENOENT);

		err = filc_read_from_tree_leaves(f_ctx, parent_fti);
		return_if_err(err);
	}
	return 0;
}

static int filc_read_by_head1(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};
		size_t len                   = 0;

		filc_resolve_head1_leaf(f_ctx, &fdr);

		err = filc_read_from_leaf(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_read_by_head2(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head2_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};
		size_t len                   = 0;

		filc_resolve_head2_leaf(f_ctx, &fdr);

		err = filc_read_from_leaf(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_read_by_heads(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_read_by_head1(f_ctx);
	return_if_err(err);

	err = filc_read_by_head2(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_read_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_read_by_heads(f_ctx);
	return_if_err(err);

	err = filc_read_by_tree(f_ctx);
	return_if_err(err);

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
		container_of(rwi, struct silofs_read_iter, rwi);

	return silofs_unconst(rdi);
}

static int read_iter_check_iovec(const struct silofs_read_iter *rdi,
                                 const struct silofs_iovec *iovec)
{
	if ((iovec->iov_fd >= 0) && (iovec->iov_off < 0)) {
		return -SILOFS_EINVAL;
	}
	if ((rdi->dat_len + iovec->iov.iov_len) > rdi->dat_max) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int read_iter_actor(struct silofs_rwiter_ctx *rwi,
                           const struct silofs_iovec *iovec)
{
	struct silofs_read_iter *rdi = read_iter_of(rwi);
	int err;

	err = read_iter_check_iovec(rdi, iovec);
	return_if_err(err);

	err = silofs_iovec_copy_into(iovec, rdi->dat + rdi->dat_len);
	return_if_err(err);

	rdi->dat_len += iovec->iov.iov_len;
	return 0;
}

static off_t rw_iter_end(const struct silofs_rwiter_ctx *rwi)
{
	return silofs_off_end(rwi->off, rwi->len);
}

static void filc_update_with_rw_iter(struct silofs_file_ctx *f_ctx,
                                     struct silofs_rwiter_ctx *rwi_ctx)
{
	const off_t end = rw_iter_end(rwi_ctx);
	const off_t isz = silofs_ii_size(f_ctx->ii);

	f_ctx->rwi_ctx = rwi_ctx;
	f_ctx->len     = rwi_ctx->len;
	f_ctx->beg     = rwi_ctx->off;
	f_ctx->off     = rwi_ctx->off;
	if (f_ctx->op == SILOFS_FILE_OP_READ) {
		f_ctx->end = silofs_off_min(end, isz);
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
		filc_update_post_io(f_ctx);
	}
	return err;
}

int silofs_do_read_iter(struct silofs_task_ctx *task,
                        struct silofs_inode_info *ii, int o_flags,
                        struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_READ,
		.stg_mode     = SILOFS_STG_CUR,
		.task         = task,
		.ii           = ii,
		.with_backref = 1,
		.o_flags      = o_flags,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, rwi);
	filc_incref(&f_ctx);
	ret = filc_read_iter(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

int silofs_do_read(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                   void *buf, size_t len, off_t off, int o_flags,
                   size_t *out_len)
{
	struct silofs_read_iter rdi = {
		.dat_len   = 0,
		.rwi.actor = read_iter_actor,
		.rwi.len   = len,
		.rwi.off   = off,
		.dat       = buf,
		.dat_max   = len,
	};
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_READ,
		.stg_mode     = SILOFS_STG_CUR,
		.task         = task,
		.ii           = ii,
		.with_backref = 0,
		.o_flags      = o_flags,
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
                                   const struct silofs_laddr *laddr)
{
	return silofs_clear_unwritten_flnode(f_ctx->task, laddr, f_ctx->ii);
}

static int filc_clear_unwritten_of(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_info *fli)
{
	int ret = 0;

	if (fli != nullptr) {
		const struct silofs_laddr *laddr = fli_laddr(fli);

		fli_incref(fli);
		ret = filc_clear_unwritten_at(f_ctx, laddr);
		if (ret == 0) {
			filc_setdirty_flnode(f_ctx, fli);
		}
		fli_decref(fli);
	}
	return ret;
}

static int
filc_claim_flnode(const struct silofs_file_ctx *f_ctx, enum silofs_ltype ltype,
                  struct silofs_laddr *out_laddr)
{
	return silofs_claim_flnode(f_ctx->task, ltype, f_ctx->ii, out_laddr);
}

static int filc_share_flnode(const struct silofs_file_ctx *f_ctx,
                             const struct silofs_laddr *laddr)
{
	return silofs_share_flnode(f_ctx->task, laddr, f_ctx->ii);
}

static int filc_unshare_flnode(const struct silofs_file_ctx *f_ctx,
                               const struct silofs_laddr *laddr)
{
	return silofs_unshare_flnode(f_ctx->task, laddr, f_ctx->ii);
}

static int filc_remove_flnode(const struct silofs_file_ctx *f_ctx,
                              const struct silofs_laddr *laddr)
{
	return silofs_remove_flnode(f_ctx->task, laddr, f_ctx->ii);
}

static int filc_spawn_ftnode(const struct silofs_file_ctx *f_ctx,
                             struct silofs_ftnode_info **out_fti)
{
	return silofs_spawn_ftnode(f_ctx->task, f_ctx->ii, out_fti);
}

static int filc_remove_ftnode(const struct silofs_file_ctx *f_ctx,
                              struct silofs_ftnode_info *fti)
{
	struct silofs_laddr laddr;

	fti_get_laddr(fti, &laddr);
	return silofs_remove_ftnode(f_ctx->task, &laddr, f_ctx->ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void filc_update_head1_leaf_by(const struct silofs_file_ctx *f_ctx,
                                      const struct silofs_flnode_ref *fdr)
{
	filc_set_head1_leaf_at(f_ctx, fdr->slot_idx, &fdr->laddr);
	silofs_ii_setdirty(f_ctx->ii);
}

static void filc_update_head2_leaf_by(const struct silofs_file_ctx *f_ctx,
                                      const struct silofs_flnode_ref *fdr)
{
	filc_set_head2_leaf_at(f_ctx, fdr->slot_idx, &fdr->laddr);
	silofs_ii_setdirty(f_ctx->ii);
}

static void filc_update_tree_root(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr)
{
	filc_set_tree_root_at(f_ctx, laddr);
	silofs_ii_setdirty(f_ctx->ii);
}

static void filc_update_iblocks(const struct silofs_file_ctx *f_ctx,
                                const struct silofs_laddr *laddr, long dif)
{
	silofs_update_iblocks_of(f_ctx->task, f_ctx->ii, laddr->ltype, dif);
}

static int
filc_spawn_setup_ftnode(const struct silofs_file_ctx *f_ctx, off_t off,
                        size_t height, struct silofs_ftnode_info **out_fti)
{
	int err;

	err = filc_spawn_ftnode(f_ctx, out_fti);
	return_if_err(err);

	fti_setup(*out_fti, f_ctx->ii, off, height);
	fti_setdirty(*out_fti, f_ctx->ii);
	return 0;
}

static int
filc_spawn_root_ftnode(const struct silofs_file_ctx *f_ctx, size_t height,
                       struct silofs_ftnode_info **out_fti)
{
	silofs_assert_ge(height, 2);

	return filc_spawn_setup_ftnode(f_ctx, 0, height, out_fti);
}

static int filc_spawn_bind_ftnode(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info *parent_fti,
                                  struct silofs_ftnode_info **out_fti)
{
	const off_t file_pos = f_ctx->off;
	const size_t height  = fti_height(parent_fti);
	int err;

	err = filc_spawn_setup_ftnode(f_ctx, file_pos, height - 1, out_fti);
	return_if_err(err);

	fti_bind_finode(parent_fti, file_pos, *out_fti);
	fti_setdirty(parent_fti, f_ctx->ii);
	return 0;
}

static int filc_create_flnode_space(const struct silofs_file_ctx *f_ctx,
                                    enum silofs_ltype ltype,
                                    struct silofs_laddr *out_laddr)
{
	int err;

	err = filc_claim_flnode(f_ctx, ltype, out_laddr);
	return_if_err(err);

	filc_update_iblocks(f_ctx, out_laddr, 1);
	return 0;
}

static int filc_create_head1_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	int err;

	err = filc_create_flnode_space(f_ctx, SILOFS_LTYPE_DATA1K, &laddr);
	return_if_err(err);

	fdr_setup1(out_fdr, f_ctx->ii, &laddr, f_ctx->off, f_ctx->end);
	filc_update_head1_leaf_by(f_ctx, out_fdr);
	return 0;
}

static int filc_create_head2_leaf_space(const struct silofs_file_ctx *f_ctx,
                                        struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	int err;

	err = filc_create_flnode_space(f_ctx, SILOFS_LTYPE_DATA4K, &laddr);
	return_if_err(err);

	fdr_setup2(out_fdr, f_ctx->ii, &laddr, f_ctx->off, f_ctx->end);
	filc_update_head2_leaf_by(f_ctx, out_fdr);
	return 0;
}

static int
filc_do_create_tree_leaf_space(const struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *parent_fti)
{
	struct silofs_laddr laddr = {};
	int err;

	err = filc_create_flnode_space(f_ctx, SILOFS_LTYPE_DATA64K, &laddr);
	return_if_err(err);

	fti_bind_child(parent_fti, f_ctx->off, &laddr);
	fti_setdirty(parent_fti, f_ctx->ii);
	return 0;
}

static int filc_create_tree_leaf_space(const struct silofs_file_ctx *f_ctx,
                                       struct silofs_ftnode_info *parent_fti)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_create_tree_leaf_space(f_ctx, parent_fti);
	fti_decref(parent_fti);
	return ret;
}

static void filc_bind_sub_tree(const struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *fti)
{
	struct silofs_laddr laddr = {};

	filc_tree_root_of(f_ctx, &laddr);
	fti_assign_child_at(fti, 0, &laddr);
	fti_setdirty(fti, f_ctx->ii);

	filc_update_tree_root(f_ctx, fti_laddr(fti));
	fti_bind_finode(nullptr, 0, fti);
}

static int filc_resolve_tree_root(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info **out_fti)
{
	int ret = 0;

	if (filc_has_tree_root(f_ctx)) {
		ret = filc_stage_root_ftnode(f_ctx, out_fti);
	}
	return ret;
}

static int filc_create_tree_spine(const struct silofs_file_ctx *f_ctx)
{
	struct silofs_ftnode_info *fti = nullptr;
	size_t height_want;
	size_t height_curr;
	int err;

	err = filc_resolve_tree_root(f_ctx, &fti);
	return_if_err(err);

	height_want = off_to_tree_height(f_ctx->off);
	height_curr = fti ? fti_height(fti) : 1;
	while (height_curr < height_want) {
		err = filc_spawn_root_ftnode(f_ctx, ++height_curr, &fti);
		return_if_err(err);

		filc_bind_sub_tree(f_ctx, fti);
	}
	return 0;
}

static int filc_do_require_tree_node(const struct silofs_file_ctx *f_ctx,
                                     struct silofs_ftnode_info *parent_fti,
                                     struct silofs_ftnode_info **out_fti)
{
	struct silofs_laddr laddr;
	int ret;

	filc_resolve_tree_node(f_ctx, parent_fti, &laddr);
	if (!laddr_isnull(&laddr)) {
		ret = filc_stage_ftnode(f_ctx, &laddr, out_fti);
	} else {
		ret = filc_spawn_bind_ftnode(f_ctx, parent_fti, out_fti);
	}
	return ret;
}

static int filc_require_tree_node(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info *parent_fti,
                                  struct silofs_ftnode_info **out_fti)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_require_tree_node(f_ctx, parent_fti, out_fti);
	fti_decref(parent_fti);
	return ret;
}

static int filc_require_tree_path(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info **out_fti)
{
	struct silofs_ftnode_info *fti;
	size_t height;
	int err;

	err = filc_stage_root_ftnode(f_ctx, &fti);
	return_if_err(err);

	height = fti_height(fti);
	for (size_t level = height; level > 0; --level) {
		if (fti_isbottom(fti)) {
			*out_fti = fti;
			return 0;
		}
		err = filc_require_tree_node(f_ctx, fti, &fti);
		return_if_err(err);
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_require_tree(const struct silofs_file_ctx *f_ctx,
                             struct silofs_ftnode_info **out_fti)
{
	int err;

	err = filc_create_tree_spine(f_ctx);
	return_if_err(err);

	err = filc_require_tree_path(f_ctx, out_fti);
	return_if_err(err);

	return 0;
}

static int
filc_do_write_flnode_by_copy(const struct silofs_file_ctx *f_ctx,
                             struct silofs_flnode_info *fli, size_t *out_sz)
{
	int err;

	err = filc_import_data_by_flnode(f_ctx, fli, out_sz);
	return_if_err(err);

	err = filc_clear_unwritten_of(f_ctx, fli);
	return_if_err(err);

	return 0;
}

static int
filc_write_flnode_by_copy(const struct silofs_file_ctx *f_ctx,
                          struct silofs_flnode_info *fli, size_t *out_sz)
{
	int err;

	fli_incref(fli);
	err = filc_do_write_flnode_by_copy(f_ctx, fli, out_sz);
	fli_decref(fli);
	return err;
}

static int filc_pre_write_leaf(const struct silofs_file_ctx *f_ctx,
                               struct silofs_flnode_ref *fdr, size_t len)
{
	int err;

	err = filc_update_pre_write_leaf_by(f_ctx, fdr, len);
	return_if_err(err);

	if (!fdr->unwritten || !fdr->partial) {
		return 0;
	}

	err = filc_zero_data_leaf_at(f_ctx, &fdr->laddr);
	return_if_err(err);

	return 0;
}

static int filc_require_mut_by(const struct silofs_file_ctx *f_ctx,
                               const struct silofs_flnode_ref *fdr)
{
	int ret = 0;

	if (!laddr_isnull(&fdr->laddr)) {
		ret = filc_require_mut_laddr(f_ctx, &fdr->laddr);
	}
	return ret;
}

static int filc_do_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                     struct silofs_ftnode_info *parent_fti,
                                     struct silofs_flnode_ref *out_fdr)
{
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fti, out_fdr);
	if (out_fdr->has_data) {
		return filc_require_mut_by(f_ctx, out_fdr);
	}

	err = filc_create_tree_leaf_space(f_ctx, parent_fti);
	return_if_err(err);

	filc_resolve_tree_leaf(f_ctx, parent_fti, out_fdr);
	return 0;
}

static int filc_require_tree_leaf(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_ftnode_info *parent_fti,
                                  struct silofs_flnode_ref *out_fdr)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_require_tree_leaf(f_ctx, parent_fti, out_fdr);
	fti_decref(parent_fti);
	return ret;
}

static int
filc_write_to_flnode_by(const struct silofs_file_ctx *f_ctx,
                        struct silofs_flnode_ref *fdr, size_t *out_len)
{
	struct silofs_flnode_info *fli = nullptr;
	int err;

	err = filc_pre_write_leaf(f_ctx, fdr, 0);
	return_if_err(err);

	err = filc_stage_flnode_by(f_ctx, fdr, &fli);
	return_if_err(err);

	err = filc_write_flnode_by_copy(f_ctx, fli, out_len);
	return_if_err(err);

	fdr->unwritten = false;
	return 0;
}

static int filc_detect_shared_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_ref *fdr)
{
	int ret = 0;

	if (fdr->tree && fdr->has_data && !fdr->shared) {
		ret = silofs_isshared_flnode(f_ctx->task, &fdr->laddr,
		                             f_ctx->ii, &fdr->shared);
	}
	return ret;
}

static int filc_do_write_to_tree_leaves(struct silofs_file_ctx *f_ctx,
                                        struct silofs_ftnode_info *parent_fti)
{
	struct silofs_flnode_ref fdr = { .file_pos = -1 };
	int err;

	while (filc_has_more_io(f_ctx)) {
		size_t len = 0;

		err = filc_require_tree_leaf(f_ctx, parent_fti, &fdr);
		return_if_err(err);

		err = filc_detect_shared_by(f_ctx, &fdr);
		return_if_err(err);

		err = filc_unshare_flnode_by(f_ctx, &fdr);
		return_if_err(err);

		err = filc_write_to_flnode_by(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);

		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int filc_write_to_tree_leaves(struct silofs_file_ctx *f_ctx,
                                     struct silofs_ftnode_info *parent_fti)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_write_to_tree_leaves(f_ctx, parent_fti);
	fti_decref(parent_fti);
	return ret;
}

static int filc_write_by_tree(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_more_io(f_ctx)) {
		struct silofs_ftnode_info *fti = nullptr;

		err = filc_require_tree(f_ctx, &fti);
		return_if_err(err);

		err = filc_write_to_tree_leaves(f_ctx, fti);
		return_if_err(err);
	}
	return 0;
}

static int filc_require_head1_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	int ret;

	filc_resolve_head1_leaf(f_ctx, out_fdr);
	if (out_fdr->has_data) {
		ret = filc_require_mut_by(f_ctx, out_fdr);
	} else {
		ret = filc_create_head1_leaf_space(f_ctx, out_fdr);
	}
	return ret;
}

static int filc_require_head2_leaf(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *out_fdr)
{
	int ret;

	filc_resolve_head2_leaf(f_ctx, out_fdr);
	if (out_fdr->has_data) {
		ret = filc_require_mut_by(f_ctx, out_fdr);
	} else {
		ret = filc_create_head2_leaf_space(f_ctx, out_fdr);
	}
	return ret;
}

static int filc_write_by_head1(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};
		size_t len                   = 0;

		err = filc_require_head1_leaf(f_ctx, &fdr);
		return_if_err(err);

		err = filc_write_to_flnode_by(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_write_by_head2(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head2_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};
		size_t len;

		err = filc_require_head2_leaf(f_ctx, &fdr);
		return_if_err(err);

		len = 0;
		err = filc_write_to_flnode_by(f_ctx, &fdr, &len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int filc_write_by_heads(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_write_by_head1(f_ctx);
	return_if_err(err);

	err = filc_write_by_head2(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_write_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_write_by_heads(f_ctx);
	return_if_err(err);

	err = filc_write_by_tree(f_ctx);
	return_if_err(err);

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
		container_of(rwi, struct silofs_write_iter, rwi);

	return silofs_unconst(wri);
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
	return silofs_flush_dirty_of(f_ctx->task, f_ctx->ii, flags);
}

static int filc_flush_dirty_now(const struct silofs_file_ctx *f_ctx)
{
	return filc_flush_dirty_of(f_ctx, SILOFS_CTLF_NOW);
}

static int filc_post_write_iter(const struct silofs_file_ctx *f_ctx)
{
	int ret = 0;

	if (f_ctx->o_flags & (O_SYNC | O_DSYNC)) {
		ret = filc_flush_dirty_of(f_ctx, SILOFS_CTLF_FSYNC);
	}
	return ret;
}

static void filc_update_kill_suidgid(struct silofs_file_ctx *f_ctx, int err)
{
	if (err || (f_ctx->off <= f_ctx->beg)) {
		f_ctx->kill_suidgid = false;
	}
}

static int filc_write_iter(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	return_if_err(err);

	err = filc_write_data(f_ctx);
	goto_out_if_err(err);

	err = filc_post_write_iter(f_ctx);
	goto_out_if_err(err);
out:
	filc_update_kill_suidgid(f_ctx, err);
	filc_update_post_io(f_ctx);
	return err;
}

int silofs_do_write_iter(struct silofs_task_ctx *task,
                         struct silofs_inode_info *ii, int o_flags,
                         bool kill_suidgid, struct silofs_rwiter_ctx *rwi)
{
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_WRITE,
		.stg_mode     = SILOFS_STG_COW,
		.task         = task,
		.ii           = ii,
		.with_backref = 1,
		.o_flags      = o_flags,
		.kill_suidgid = kill_suidgid,
	};
	int ret;

	filc_update_with_rw_iter(&f_ctx, rwi);

	filc_incref(&f_ctx);
	ret = filc_write_iter(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

int silofs_do_write(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    const void *buf, size_t len, off_t off, int o_flags,
                    bool kill_suidgid, size_t *out_len)
{
	struct silofs_write_iter wri = {
		.rwi.actor = write_iter_actor,
		.rwi.len   = len,
		.rwi.off   = off,
		.dat       = buf,
		.dat_len   = 0,
		.dat_max   = len,
	};
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_WRITE,
		.stg_mode     = SILOFS_STG_COW,
		.task         = task,
		.ii           = ii,
		.with_backref = 0,
		.o_flags      = o_flags,
		.kill_suidgid = kill_suidgid,
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

int silofs_do_rdwr_post(const struct silofs_task_ctx *task, int wr_mode,
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
                                    struct silofs_ftnode_info *fti);

static int filc_discard_data_leaf(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_laddr *laddr)
{
	int err;

	if (laddr_isnull(laddr)) {
		return 0;
	}

	err = filc_remove_flnode(f_ctx, laddr);
	return_if_err(err);

	filc_update_iblocks(f_ctx, laddr, -1);
	return 0;
}

static int filc_drop_subtree(struct silofs_file_ctx *f_ctx,
                             const struct silofs_laddr *laddr)
{
	struct silofs_ftnode_info *fti = nullptr;
	int err;

	if (laddr_isnull(laddr)) {
		return 0;
	}
	err = filc_stage_ftnode(f_ctx, laddr, &fti);
	return_if_err(err);

	err = filc_drop_remove_subtree(f_ctx, fti);
	return_if_err(err);

	return 0;
}

static int filc_drop_subtree_at(struct silofs_file_ctx *f_ctx,
                                struct silofs_ftnode_info *fti, size_t slot)
{
	struct silofs_laddr laddr;
	int err;

	fti_resolve_child_by_slot(fti, slot, &laddr);
	if (laddr_isnull(&laddr)) {
		return 0;
	}

	if (fti_isbottom(fti)) {
		err = filc_discard_data_leaf(f_ctx, &laddr);
		return_if_err(err);
	} else {
		err = filc_drop_subtree(f_ctx, &laddr);
		return_if_err(err);
	}

	fti_clear_subtree_mappings(fti, slot);
	return 0;
}

static int filc_drop_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *fti)
{
	const size_t nslots_max = ftn_nchilds_max(fti->ftn);
	int err                 = 0;

	fti_incref(fti);
	for (size_t slot = 0; slot < nslots_max; ++slot) {
		if (!ftn_nactive_childs(fti->ftn)) {
			break;
		}
		err = filc_drop_subtree_at(f_ctx, fti, slot);
		if (err) {
			break;
		}
	}
	fti_decref(fti);
	return err;
}

static int
filc_drop_ftnode(struct silofs_file_ctx *f_ctx, struct silofs_ftnode_info *fti)
{
	int err = 0;

	ftn_dec_refcnt(fti->ftn);
	if (!ftn_refcnt(fti->ftn)) {
		err = filc_remove_ftnode(f_ctx, fti);
	}
	return err;
}

static int filc_drop_remove_subtree(struct silofs_file_ctx *f_ctx,
                                    struct silofs_ftnode_info *fti)
{
	int err;

	err = filc_drop_recursive(f_ctx, fti);
	return_if_err(err);

	err = filc_drop_ftnode(f_ctx, fti);
	return_if_err(err);

	return 0;
}

static void filc_reset_tree_root(struct silofs_file_ctx *f_ctx)
{
	filc_set_tree_root_at(f_ctx, silofs_laddr_none());
	silofs_ii_setdirty(f_ctx->ii);
}

static int filc_drop_tree_map(struct silofs_file_ctx *f_ctx)
{
	int err;

	if (filc_has_tree_root(f_ctx)) {
		struct silofs_ftnode_info *fti = nullptr;

		err = filc_stage_root_ftnode(f_ctx, &fti);
		return_if_err(err);

		err = filc_drop_remove_subtree(f_ctx, fti);
		return_if_err(err);

		filc_reset_tree_root(f_ctx);
	}
	return 0;
}

static int filc_drop_head1_leaf_at(struct silofs_file_ctx *f_ctx, size_t slot)
{
	struct silofs_laddr laddr;

	filc_head1_leaf_at(f_ctx, slot, &laddr);
	return filc_discard_data_leaf(f_ctx, &laddr);
}

static int filc_drop_head2_leaf_at(struct silofs_file_ctx *f_ctx, size_t slot)
{
	struct silofs_laddr laddr;

	filc_head2_leaf_at(f_ctx, slot, &laddr);
	return filc_discard_data_leaf(f_ctx, &laddr);
}

static void
filc_reset_head1_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot)
{
	filc_set_head1_leaf_at(f_ctx, slot, silofs_laddr_none());
	silofs_ii_setdirty(f_ctx->ii);
}

static void
filc_reset_head2_leaf_at(const struct silofs_file_ctx *f_ctx, size_t slot)
{
	filc_set_head2_leaf_at(f_ctx, slot, silofs_laddr_none());
	silofs_ii_setdirty(f_ctx->ii);
}

static void filc_reset_head1_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_flnode_ref *fdr)
{
	filc_reset_head1_leaf_at(f_ctx, fdr->slot_idx);
}

static void filc_reset_head2_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_flnode_ref *fdr)
{
	filc_reset_head2_leaf_at(f_ctx, fdr->slot_idx);
}

static void filc_clear_subtree_mappings_by(const struct silofs_file_ctx *f_ctx,
                                           const struct silofs_flnode_ref *fdr)
{
	fti_clear_subtree_mappings(fdr->parent_fti, fdr->slot_idx);
	fti_setdirty(fdr->parent_fti, f_ctx->ii);
}

static int filc_drop_head1_leafs(struct silofs_file_ctx *f_ctx)
{
	int err;

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD1_NLEAF; ++slot) {
		err = filc_drop_head1_leaf_at(f_ctx, slot);
		return_if_err(err);

		filc_reset_head1_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int filc_drop_head2_leafs(struct silofs_file_ctx *f_ctx)
{
	int err;

	for (size_t slot = 0; slot < SILOFS_FILE_HEAD2_NLEAF; ++slot) {
		err = filc_drop_head2_leaf_at(f_ctx, slot);
		return_if_err(err);

		filc_reset_head2_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int filc_drop_heads(struct silofs_file_ctx *f_ctx)
{
	int err;

	if (filc_ftype1_mode(f_ctx)) {
		err = filc_drop_head1_leafs(f_ctx);
		return_if_err(err);

		err = filc_drop_head2_leafs(f_ctx);
		return_if_err(err);
	}

	return 0;
}

static int filc_drop_data_and_meta(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_drop_heads(f_ctx);
	return_if_err(err);

	err = filc_drop_tree_map(f_ctx);
	return_if_err(err);

	return 0;
}

int silofs_drop_reg(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	struct silofs_file_ctx f_ctx = {
		.op       = SILOFS_FILE_OP_DROP,
		.task     = task,
		.ii       = ii,
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
                                        const struct silofs_flnode_ref *fdr)
{
	enum silofs_ltype ltype = fdr_ltype(fdr);
	const off_t pos         = fdr->file_pos;
	const size_t len        = len_of_data(pos, f_ctx->end, ltype);
	const off_t off_in_dn   = off_in_data(pos, ltype);
	int err;

	fti_incref(fdr->parent_fti);
	err = filc_zero_flnode_range(f_ctx, &fdr->laddr, off_in_dn, len);
	fti_decref(fdr->parent_fti);
	return err;
}

static int filc_discard_partial_by(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *fdr)
{
	int err;

	err = filc_unshare_flnode_by(f_ctx, fdr);
	return_if_err(err);

	err = filc_zero_data_leaf_range_by(f_ctx, fdr);
	return_if_err(err);

	return 0;
}

static int filc_discard_data_leaf_by(const struct silofs_file_ctx *f_ctx,
                                     const struct silofs_flnode_ref *fdr)
{
	int err;

	fti_incref(fdr->parent_fti);
	err = filc_discard_data_leaf(f_ctx, &fdr->laddr);
	fti_decref(fdr->parent_fti);
	return err;
}

static int filc_discard_entire_by(const struct silofs_file_ctx *f_ctx,
                                  const struct silofs_flnode_ref *fdr)
{
	int err;

	err = filc_discard_data_leaf_by(f_ctx, fdr);
	return_if_err(err);

	if (fdr->head1) {
		filc_reset_head1_leaf_by(f_ctx, fdr);
	} else if (fdr->head2) {
		filc_reset_head2_leaf_by(f_ctx, fdr);
	} else if (fdr->tree && fdr->parent_fti) {
		filc_clear_subtree_mappings_by(f_ctx, fdr);
	}
	return 0;
}

static int filc_discard_via_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                         const struct silofs_flnode_ref *fdr)
{
	return silofs_mark_unwritten_flnode(f_ctx->task, &fdr->laddr,
	                                    f_ctx->ii);
}

static bool filc_zero_range_mode(const struct silofs_file_ctx *f_ctx)
{
	return fl_mode_zero_range(f_ctx->fl_mode);
}

static int filc_discard_data_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_flnode_ref *fdr)
{
	int err;

	if (fdr->has_data) {
		err = filc_detect_shared_by(f_ctx, fdr);
		return_if_err(err);

		if (fdr->partial) {
			err = filc_discard_partial_by(f_ctx, fdr);
		} else if (!fdr->shared && filc_zero_range_mode(f_ctx)) {
			err = filc_discard_via_unwritten_by(f_ctx, fdr);
		} else {
			err = filc_discard_entire_by(f_ctx, fdr);
		}
		return_if_err(err);
	}
	return 0;
}

static int filc_discard_by_tree(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fdr;
	int err;

	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree(f_ctx, &fdr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		return_if_err(err);

		err = filc_discard_data_by(f_ctx, &fdr);
		return_if_err(err);

		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_by_head1(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};

		filc_resolve_head1_leaf(f_ctx, &fdr);

		err = filc_discard_data_by(f_ctx, &fdr);
		return_if_err(err);

		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_by_head2(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_head2_leaves_io(f_ctx)) {
		struct silofs_flnode_ref fdr = {};

		filc_resolve_head2_leaf(f_ctx, &fdr);

		err = filc_discard_data_by(f_ctx, &fdr);
		return_if_err(err);

		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_discard_by_heads(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_discard_by_head1(f_ctx);
	return_if_err(err);

	err = filc_discard_by_head2(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_discard_data(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_discard_by_heads(f_ctx);
	return_if_err(err);

	err = filc_discard_by_tree(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_discard_unused_meta(struct silofs_file_ctx *f_ctx)
{
	return (f_ctx->beg == 0) ? filc_drop_data_and_meta(f_ctx) : 0;
}

static int
filc_resolve_heads_end(const struct silofs_file_ctx *f_ctx, off_t *out_end)
{
	struct silofs_laddr laddr;
	size_t slot;

	*out_end = 0;
	if (!filc_ftype1_mode(f_ctx)) {
		goto out;
	}
	slot = SILOFS_FILE_HEAD2_NLEAF;
	while (slot-- > 0) {
		filc_head2_leaf_at(f_ctx, slot, &laddr);
		if (!laddr_isnull(&laddr)) {
			*out_end = off_head2_end_of(slot);
			goto out;
		}
	}
	slot = SILOFS_FILE_HEAD1_NLEAF;
	while (slot-- > 0) {
		filc_head1_leaf_at(f_ctx, slot, &laddr);
		if (!laddr_isnull(&laddr)) {
			*out_end = off_head1_end_of(slot);
			goto out;
		}
	}
out:
	return 0;
}

static int
filc_resolve_tree_end(const struct silofs_file_ctx *f_ctx, off_t *out_end)
{
	struct silofs_ftnode_info *fti = nullptr;
	int err;

	*out_end = 0;
	if (!filc_has_tree_root(f_ctx)) {
		return 0;
	}
	err = filc_stage_root_ftnode(f_ctx, &fti);
	return_if_err(err);

	*out_end = ftn_end(fti->ftn);
	return 0;
}

static int filc_resolve_truncate_end(struct silofs_file_ctx *f_ctx)
{
	off_t lend = 0;
	off_t tend = 0;
	int err;

	err = filc_resolve_heads_end(f_ctx, &lend);
	return_if_err(err);

	err = filc_resolve_tree_end(f_ctx, &tend);
	return_if_err(err);

	f_ctx->end = off_max3(f_ctx->off, lend, tend);
	return 0;
}

static int filc_truncate(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_check_file_io(f_ctx);
	return_if_err(err);

	err = filc_resolve_truncate_end(f_ctx);
	return_if_err(err);

	err = filc_discard_data(f_ctx);
	return_if_err(err);

	err = filc_discard_unused_meta(f_ctx);
	return_if_err(err);

	filc_update_post_io(f_ctx);
	return 0;
}

int silofs_do_truncate(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii, off_t off,
                       bool kill_suidgid)
{
	const off_t isp              = silofs_ii_span(ii);
	const size_t len             = (off < isp) ? off_ulen(off, isp) : 0;
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_TRUNC,
		.stg_mode     = SILOFS_STG_COW,
		.task         = task,
		.ii           = ii,
		.len          = len,
		.beg          = off,
		.off          = off,
		.end          = off_end(off, len),
		.kill_suidgid = kill_suidgid,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_truncate(&f_ctx);
	filc_decref(&f_ctx);

	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_lseek_data_leaf(struct silofs_file_ctx *f_ctx,
                                struct silofs_flnode_ref *out_fdr)
{
	int err;

	fdr_reset(out_fdr);
	err = filc_seek_data_by_heads(f_ctx, out_fdr);
	if (!err || (err != -SILOFS_ENOENT)) {
		return err;
	}
	err = filc_seek_by_tree(f_ctx, out_fdr);
	if (err) {
		return err;
	}
	return 0;
}

static int filc_lseek_data(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fdr;
	off_t isz;
	int err;

	isz = silofs_ii_size(f_ctx->ii);
	err = filc_lseek_data_leaf(f_ctx, &fdr);
	if (err == -SILOFS_ENOENT) {
		f_ctx->off = isz;
		return -SILOFS_ENXIO;
	}
	if (err) {
		return err;
	}
	f_ctx->off = off_clamp(fdr.file_pos, f_ctx->off, isz);
	return 0;
}

static int filc_lseek_hole_noleaf(struct silofs_file_ctx *f_ctx,
                                  struct silofs_flnode_ref *fdr)
{
	int err;

	err = filc_seek_hole_by_heads(f_ctx, fdr);
	if (err == -SILOFS_ENOENT) {
		err = filc_seek_by_tree(f_ctx, fdr);
	}
	return err;
}

static int filc_lseek_hole(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fdr = { .file_pos = -1 };
	off_t isz;
	int err;

	isz = silofs_ii_size(f_ctx->ii);
	err = filc_lseek_hole_noleaf(f_ctx, &fdr);
	if (err == 0) {
		f_ctx->off = off_clamp(fdr.file_pos, f_ctx->off, isz);
	} else if (err == -SILOFS_ENOENT) {
		f_ctx->off = isz;
		err        = 0;
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
	return_if_err(err);

	if (filc_is_seek_data(f_ctx)) {
		err = filc_lseek_data(f_ctx);
		return_if_err(err);
	} else if (filc_is_seek_hole(f_ctx)) {
		err = filc_lseek_hole(f_ctx);
		return_if_err(err);
	} else {
		err = filc_lseek_notsupp(f_ctx);
		return_if_err(err);
	}
	return 0;
}

int silofs_do_lseek(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    off_t off, int whence, off_t *out_off)
{
	struct silofs_file_ctx f_ctx = {
		.op       = SILOFS_FILE_OP_LSEEK,
		.stg_mode = SILOFS_STG_CUR,
		.task     = task,
		.ii       = ii,
		.len      = 0,
		.beg      = off,
		.off      = off,
		.end      = silofs_ii_size(ii),
		.whence   = whence,

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
 * TODO-0012: Proper handling for FALLOC_FL_KEEP_SIZE beyond file size.
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
                                      struct silofs_ftnode_info *parent_fti)
{
	struct silofs_flnode_ref fdr;
	int err;

	filc_resolve_tree_leaf(f_ctx, parent_fti, &fdr);
	if (fdr.has_data) {
		return filc_require_mut_by(f_ctx, &fdr);
	}

	err = filc_create_flnode_space(f_ctx, SILOFS_LTYPE_DATA64K,
	                               &fdr.laddr);
	return_if_err(err);

	fti_bind_child(parent_fti, f_ctx->off, &fdr.laddr);
	fti_setdirty(parent_fti, f_ctx->ii);
	return 0;
}

static int filc_reserve_tree_leaves(struct silofs_file_ctx *f_ctx,
                                    struct silofs_ftnode_info *parent_fti)
{
	int ret           = 0;
	bool next_mapping = false;

	fti_incref(parent_fti);
	while (filc_has_more_io(f_ctx) && !next_mapping) {
		ret = filc_create_bind_tree_leaf(f_ctx, parent_fti);
		if (ret) {
			break;
		}
		filc_advance_to_next(f_ctx);
		next_mapping = filc_ismapping_boundaries(f_ctx);
	}
	fti_decref(parent_fti);
	return ret;
}

static int filc_reserve_leaves(struct silofs_file_ctx *f_ctx)
{
	struct silofs_ftnode_info *fti = nullptr;
	size_t height;
	int err;

	err = filc_stage_root_ftnode(f_ctx, &fti);
	return_if_err(err);

	height = fti_height(fti);
	for (size_t level = height; level > 0; --level) {
		if (fti_isbottom(fti)) {
			return filc_reserve_tree_leaves(f_ctx, fti);
		}
		err = filc_require_tree_node(f_ctx, fti, &fti);
		return_if_err(err);
	}
	return -SILOFS_EFSCORRUPTED;
}

static int filc_reserve_by_tree(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_create_tree_spine(f_ctx);
	return_if_err(err);

	err = filc_reserve_leaves(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_fallocate_reserve_by_tree(struct silofs_file_ctx *f_ctx)
{
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_reserve_by_tree(f_ctx);
		return_if_err(err);
	}
	return 0;
}

static int filc_fallocate_reserve_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fdr;
	int err;

	while (filc_has_head1_leaves_io(f_ctx)) {
		err = filc_require_head1_leaf(f_ctx, &fdr);
		return_if_err(err);

		filc_advance_to_next(f_ctx);
	}
	while (filc_has_head2_leaves_io(f_ctx)) {
		err = filc_require_head2_leaf(f_ctx, &fdr);
		return_if_err(err);

		filc_advance_to_next(f_ctx);
	}
	return 0;
}

static int filc_fallocate_reserve(struct silofs_file_ctx *f_ctx)
{
	int err;

	err = filc_fallocate_reserve_by_heads(f_ctx);
	return_if_err(err);

	err = filc_fallocate_reserve_by_tree(f_ctx);
	return_if_err(err);

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
	return_if_err(err);

	err = filc_check_fl_mode(f_ctx);
	return_if_err(err);

	err = filc_fallocate_op(f_ctx);
	return_if_err(err);

	filc_update_post_io(f_ctx);
	return 0;
}

int silofs_do_fallocate(struct silofs_task_ctx *task,
                        struct silofs_inode_info *ii, int mode, off_t off,
                        off_t len)
{
	struct silofs_file_ctx f_ctx = {
		.op           = SILOFS_FILE_OP_FALLOC,
		.stg_mode     = SILOFS_STG_COW,
		.task         = task,
		.ii           = ii,
		.len          = (size_t)len,
		.beg          = off,
		.off          = off,
		.end          = off_end(off, (size_t)len),
		.fl_mode      = mode,
		.kill_suidgid = true,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_fallocate(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool filc_emit_fiemap_ext(struct silofs_file_ctx *f_ctx,
                                 const struct silofs_laddr *laddr)
{
	struct fiemap_extent *fm_ext;
	struct fiemap *fm = f_ctx->fm;
	size_t dsz, len;
	off_t phy_pos, end;

	len = silofs_laddr_len(laddr);
	end = silofs_off_min(silofs_off_end(f_ctx->off, len), f_ctx->end);
	dsz = len_of_data(f_ctx->off, end, laddr->ltype);
	if (dsz == 0) {
		return false;
	}
	if (fm->fm_extent_count == 0) {
		fm->fm_mapped_extents++;
		return true;
	}
	if (fm->fm_mapped_extents >= fm->fm_extent_count) {
		return false;
	}
	fm_ext             = &fm->fm_extents[fm->fm_mapped_extents++];
	fm_ext->fe_flags   = FIEMAP_EXTENT_DATA_ENCRYPTED;
	fm_ext->fe_logical = (uint64_t)(f_ctx->off);

	phy_pos = laddr->off + off_in_data(f_ctx->off, laddr->ltype);
	fm_ext->fe_physical = (uint64_t)(phy_pos);
	fm_ext->fe_length   = dsz;
	return true;
}

static bool filc_emit_fiemap(struct silofs_file_ctx *f_ctx,
                             const struct silofs_flnode_ref *fdr)
{
	bool ok = true;

	if (fdr->has_data) {
		ok = filc_emit_fiemap_ext(f_ctx, &fdr->laddr);
		if (!ok) {
			f_ctx->fm_stop = true;
		}
	}
	return ok;
}

static int filc_fiemap_by_tree_leaves(struct silofs_file_ctx *f_ctx,
                                      struct silofs_ftnode_info *parent_fti)
{
	struct silofs_flnode_ref fdr;

	fti_incref(parent_fti);
	while (filc_has_more_io(f_ctx)) {
		filc_resolve_tree_leaf(f_ctx, parent_fti, &fdr);
		if (!filc_emit_fiemap(f_ctx, &fdr)) {
			break;
		}
		filc_advance_to_next(f_ctx);
		if (filc_ismapping_boundaries(f_ctx)) {
			break;
		}
	}
	fti_decref(parent_fti);
	return 0;
}

static int filc_fiemap_by_tree(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fdr;
	int err;

	while (filc_has_more_io(f_ctx)) {
		err = filc_seek_by_tree(f_ctx, &fdr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		return_if_err(err);

		err = filc_fiemap_by_tree_leaves(f_ctx, fdr.parent_fti);
		return_if_err(err);

		/* TODO: need to skip large holes */
	}
	return 0;
}

static int filc_fiemap_by_heads(struct silofs_file_ctx *f_ctx)
{
	struct silofs_flnode_ref fm;

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
	return_if_err(err);

	err = filc_fiemap_by_tree(f_ctx);
	return_if_err(err);

	return 0;
}

static int filc_check_fm_flags(const struct silofs_file_ctx *f_ctx)
{
	constexpr int fm_supported = FIEMAP_FLAG_SYNC;
	constexpr int fm_known     = //
		FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR | FIEMAP_FLAG_CACHE;

	if (f_ctx->fm_flags & ~fm_known) {
		return -SILOFS_EOPNOTSUPP;
	}
	if (f_ctx->fm_flags & ~fm_supported) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int filc_fiemap(struct silofs_file_ctx *f_ctx)
{
	int err;

	f_ctx->fm->fm_mapped_extents = 0;

	err = filc_check_file_io(f_ctx);
	return_if_err(err);

	err = filc_check_fm_flags(f_ctx);
	return_if_err(err);

	err = filc_fiemap_data(f_ctx);
	return_if_err(err);

	return 0;
}

static off_t
ii_off_end(const struct silofs_inode_info *ii, off_t off, size_t len)
{
	const off_t end = silofs_off_end(off, len);
	const off_t isz = silofs_ii_size(ii);

	return silofs_off_min(end, isz);
}

int silofs_do_fiemap(struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, struct fiemap *fm)
{
	const off_t off              = (off_t)fm->fm_start;
	const size_t len             = (size_t)fm->fm_length;
	struct silofs_file_ctx f_ctx = {
		.op       = SILOFS_FILE_OP_FIEMAP,
		.stg_mode = SILOFS_STG_CUR,
		.task     = task,
		.ii       = ii,
		.len      = len,
		.beg      = off,
		.off      = off,
		.end      = ii_off_end(ii, off, len),
		.fm       = fm,
		.fm_flags = (int)(fm->fm_flags),
		.fm_stop  = 0,
		.whence   = SEEK_DATA,
	};
	int ret;

	filc_incref(&f_ctx);
	ret = filc_fiemap(&f_ctx);
	filc_decref(&f_ctx);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_ftnode_info *parent_fti,
                                       struct silofs_flnode_ref *out_fdr);

static int filc_resolve_fpos_by_heads(struct silofs_file_ctx *f_ctx,
                                      struct silofs_flnode_ref *out_fdr)
{
	int err = 0;

	if (filc_has_head1_leaves_io(f_ctx)) {
		filc_resolve_head1_leaf(f_ctx, out_fdr);
	} else if (filc_has_head2_leaves_io(f_ctx)) {
		filc_resolve_head2_leaf(f_ctx, out_fdr);
	} else {
		err = -SILOFS_ENOENT;
	}
	return err;
}

static int
filc_resolve_fpos_recursive_at(struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *parent_fti,
                               size_t slot, struct silofs_flnode_ref *out_fdr)
{
	struct silofs_laddr laddr;
	struct silofs_ftnode_info *fti = nullptr;
	int err;

	fti_resolve_child_by_slot(parent_fti, slot, &laddr);

	err = filc_stage_ftnode(f_ctx, &laddr, &fti);
	return_if_err(err);

	err = filc_resolve_fpos_recursive(f_ctx, fti, out_fdr);
	return_if_err(err);

	return 0;
}

static int
filc_do_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                               struct silofs_ftnode_info *parent_fti,
                               struct silofs_flnode_ref *out_fdr)
{
	const off_t off = f_ctx->off;
	size_t slot;

	if (!fti_isinrange(parent_fti, off)) {
		return -SILOFS_ENOENT;
	}
	slot = fti_child_slot_of(parent_fti, off);
	if (fti_isbottom(parent_fti)) {
		filc_resolve_child_at(f_ctx, parent_fti, off, slot, out_fdr);
		return 0;
	}
	return filc_resolve_fpos_recursive_at(f_ctx, parent_fti, slot,
	                                      out_fdr);
}

static int filc_resolve_fpos_recursive(struct silofs_file_ctx *f_ctx,
                                       struct silofs_ftnode_info *parent_fti,
                                       struct silofs_flnode_ref *out_fdr)
{
	int ret;

	fti_incref(parent_fti);
	ret = filc_do_resolve_fpos_recursive(f_ctx, parent_fti, out_fdr);
	fti_decref(parent_fti);
	return ret;
}

static int filc_resolve_fpos_by_tree(struct silofs_file_ctx *f_ctx,
                                     struct silofs_flnode_ref *out_fdr)
{
	struct silofs_ftnode_info *root_fti = nullptr;
	int err;

	err = filc_check_tree_root(f_ctx);
	return_if_err(err);

	err = filc_stage_root_ftnode(f_ctx, &root_fti);
	return_if_err(err);

	err = filc_resolve_fpos_recursive(f_ctx, root_fti, out_fdr);
	return_if_err(err);

	return 0;
}

static int filc_resolve_fpos(struct silofs_file_ctx *f_ctx,
                             struct silofs_flnode_ref *out_fdr)
{
	int err;

	fdr_reset(out_fdr);
	err = filc_resolve_fpos_by_heads(f_ctx, out_fdr);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = filc_resolve_fpos_by_tree(f_ctx, out_fdr);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	fdr_noent(out_fdr, f_ctx->ii, f_ctx->off, f_ctx->end);
	return -SILOFS_ENOENT;
}

static size_t filc_copy_length_of(const struct silofs_file_ctx *f_ctx)
{
	const size_t len_to_end  = off_ulen(f_ctx->off, f_ctx->end);
	const size_t len_to_next = filc_distance_to_next(f_ctx);

	return silofs_min(len_to_end, len_to_next);
}

/*
 * FUSE (and maybe kernel's VFS) uses uint32_t for return value of
 * copy_file_range. Tested with XFS and it looks like the actual limit is
 * (INT32_MAX - PAGE_SIZE + 1) but we don't take risks here.
 *
 * TODO: investigate more on Kernel/VFS/FUSE side.
 */
enum {
	SILOFS_COPY_FILE_RANGE_MAX = 1L << 30,
};

static size_t
filc_calc_next_copy_range_len(const struct silofs_file_ctx *f_ctx_src,
                              const struct silofs_file_ctx *f_ctx_dst)
{
	const size_t src_len = filc_copy_length_of(f_ctx_src);
	const size_t dst_len = filc_copy_length_of(f_ctx_dst);
	const size_t cur_len = filc_io_length(f_ctx_dst);
	const size_t len     = silofs_min(src_len, dst_len);

	return ((cur_len + len) <= SILOFS_COPY_FILE_RANGE_MAX) ? len : 0;
}

static int filc_clear_unwritten_by(const struct silofs_file_ctx *f_ctx,
                                   struct silofs_flnode_ref *fdr,
                                   struct silofs_flnode_info *fli)
{
	int err;

	if (fdr->unwritten) {
		err = filc_clear_unwritten_of(f_ctx, fli);
		return_if_err(err);

		fdr->unwritten = false;
	}
	return 0;
}

static int filc_copy_flnode_by(const struct silofs_file_ctx *f_ctx_src,
                               struct silofs_flnode_ref *fdr_src,
                               const struct silofs_file_ctx *f_ctx_dst,
                               struct silofs_flnode_ref *fdr_dst, size_t len)
{
	struct silofs_iovec iov_src        = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_iovec iov_dst        = { .iov_off = -1, .iov_fd = -1 };
	struct silofs_flnode_info *fli_src = nullptr;
	struct silofs_flnode_info *fli_dst = nullptr;
	int err;
	bool all;

	err = filc_stage_flnode(f_ctx_src, &fdr_src->laddr, &fli_src);
	goto_out_if_err(err);
	fli_incref(fli_src);

	err = filc_stage_flnode(f_ctx_dst, &fdr_dst->laddr, &fli_dst);
	goto_out_if_err(err);
	fli_incref(fli_dst);

	all = (len == laddr_len(&fdr_src->laddr));
	filc_iovec_by_flnode(f_ctx_src, fli_src, all, &iov_src);

	all = (len == silofs_laddr_len(&fdr_dst->laddr));
	filc_iovec_by_flnode(f_ctx_dst, fli_dst, all, &iov_dst);

	err = silofs_iovec_copy_mem(&iov_src, &iov_dst, len);
	goto_out_if_err(err);

	fli_setdirty(fli_dst, f_ctx_dst->ii);

	err = filc_clear_unwritten_by(f_ctx_dst, fdr_dst, fli_dst);
	goto_out_if_err(err);

out:
	fli_decref(fli_dst);
	fli_decref(fli_src);
	return err;
}

static int filc_copy_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                             struct silofs_flnode_ref *fdr_src,
                             const struct silofs_file_ctx *f_ctx_dst,
                             struct silofs_flnode_ref *fdr_dst, size_t len)
{
	int err;

	err = filc_pre_write_leaf(f_ctx_dst, fdr_dst, len);
	if (err) {
		return err;
	}
	err = filc_pre_write_leaf(f_ctx_src, fdr_src, len);
	if (err) {
		return err;
	}
	err = filc_copy_flnode_by(f_ctx_src, fdr_src, f_ctx_dst, fdr_dst, len);
	if (err) {
		return err;
	}
	return 0;
}

static void filc_rebind_child_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_ref *fdr,
                                 const struct silofs_laddr *laddr)
{
	fti_bind_child(fdr->parent_fti, f_ctx->off, laddr);
	fti_setdirty(fdr->parent_fti, f_ctx->ii);
	silofs_laddr_assign(&fdr->laddr, laddr);
}

static int filc_do_unshare_flnode_by(const struct silofs_file_ctx *f_ctx,
                                     struct silofs_flnode_ref *fdr)
{
	struct silofs_flnode_ref fdr_new = {};
	size_t len;
	int err;

	fdr_setup(&fdr_new, f_ctx->ii, fdr->parent_fti, &fdr->laddr,
	          fdr->file_pos, f_ctx->end);

	err = filc_claim_flnode(f_ctx, fdr->laddr.ltype, &fdr_new.laddr);
	return_if_err(err);

	len = laddr_len(&fdr->laddr);
	err = filc_copy_flnode_by(f_ctx, fdr, f_ctx, &fdr_new, len);
	goto_if_err(err, out_err);

	err = filc_unshare_flnode(f_ctx, &fdr->laddr);
	goto_if_err(err, out_err);

	filc_rebind_child_by(f_ctx, fdr, &fdr_new.laddr);
	filc_update_iblocks(f_ctx, &fdr_new.laddr, 1);
	return 0;
out_err:
	filc_remove_flnode(f_ctx, &fdr_new.laddr);
	return err;
}

static int filc_unshare_flnode_by(const struct silofs_file_ctx *f_ctx,
                                  struct silofs_flnode_ref *fdr)
{
	int ret = 0;

	silofs_assert(fdr->has_data);
	if (fdr->shared && fdr->tree) {
		ret = filc_do_unshare_flnode_by(f_ctx, fdr);
	}
	return ret;
}

static int filc_require_tree_and_leaf(const struct silofs_file_ctx *f_ctx,
                                      struct silofs_flnode_ref *out_fdr)
{
	struct silofs_ftnode_info *parent_fti = nullptr;
	int err;

	err = filc_require_tree(f_ctx, &parent_fti);
	return_if_err(err);

	err = filc_require_tree_leaf(f_ctx, parent_fti, out_fdr);
	return_if_err(err);

	return 0;
}

static int filc_require_ftype1_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_ref *out_fdr)
{
	int ret;

	if (off_is_head1(f_ctx->off)) {
		ret = filc_require_head1_leaf(f_ctx, out_fdr);
	} else if (off_is_head2(f_ctx->off)) {
		ret = filc_require_head2_leaf(f_ctx, out_fdr);
	} else {
		ret = filc_require_tree_and_leaf(f_ctx, out_fdr);
	}
	return ret;
}

static int filc_require_ftype2_leaf(const struct silofs_file_ctx *f_ctx,
                                    struct silofs_flnode_ref *out_fdr)
{
	return filc_require_tree_and_leaf(f_ctx, out_fdr);
}

static int filc_require_leaf(const struct silofs_file_ctx *f_ctx,
                             struct silofs_flnode_ref *out_fdr)
{
	int ret;

	if (filc_ftype1_mode(f_ctx)) {
		ret = filc_require_ftype1_leaf(f_ctx, out_fdr);
	} else {
		ret = filc_require_ftype2_leaf(f_ctx, out_fdr);
	}
	return ret;
}

static int filc_share_flnode_by(const struct silofs_file_ctx *f_ctx_src,
                                const struct silofs_flnode_ref *fdr_src,
                                const struct silofs_file_ctx *f_ctx_dst,
                                struct silofs_flnode_ref *fdr_dst)
{
	int err;

	err = filc_share_flnode(f_ctx_src, &fdr_src->laddr);
	if (err) {
		return err;
	}
	filc_rebind_child_by(f_ctx_dst, fdr_dst, &fdr_src->laddr);
	filc_update_iblocks(f_ctx_dst, &fdr_dst->laddr, 1);
	return 0;
}

static bool filc_test_ismutable_by(const struct silofs_file_ctx *f_ctx,
                                   const struct silofs_flnode_ref *fdr)
{
	/* XXX FIXME FIXME */
	silofs_unused(f_ctx);
	silofs_unused(fdr);
	return true;
}

static bool
filc_test_may_share_leaf_by(const struct silofs_file_ctx *f_ctx,
                            const struct silofs_flnode_ref *fdr, bool is_src)
{
	if (is_src && !fdr->has_data) {
		return false;
	}
	if (!fdr->tree) {
		return false;
	}
	if (fdr->partial) {
		return false;
	}
	return filc_test_ismutable_by(f_ctx, fdr);
}

static int filc_resolve_laddr_by(const struct silofs_file_ctx *f_ctx,
                                 struct silofs_flnode_ref *fdr)
{
	/* XXX FIXME FIXME */
	silofs_unused(f_ctx);
	silofs_unused(fdr);
	return 0;
}

static int filc_require_tree_by(const struct silofs_file_ctx *f_ctx,
                                struct silofs_flnode_ref *out_fdr)
{
	struct silofs_ftnode_info *fti = nullptr;
	int err;

	err = filc_require_tree(f_ctx, &fti);
	if (err) {
		return err;
	}
	filc_resolve_tree_leaf(f_ctx, fti, out_fdr);
	return 0;
}

static int
filc_copy_range_at_leaf_by(const struct silofs_file_ctx *f_ctx_src,
                           struct silofs_flnode_ref *fdr_src,
                           const struct silofs_file_ctx *f_ctx_dst,
                           struct silofs_flnode_ref *fdr_dst, size_t len)
{
	int err;

	if (!fdr_src->has_data && fdr_dst->has_data) {
		err = filc_require_mut_by(f_ctx_dst, fdr_dst);
		return_if_err(err);

		err = filc_unshare_flnode_by(f_ctx_dst, fdr_dst);
		return_if_err(err);

		err = filc_discard_data_by(f_ctx_dst, fdr_dst);
		return_if_err(err);

	} else if (fdr_src->has_data && !fdr_dst->has_data) {
		err = filc_resolve_laddr_by(f_ctx_src, fdr_src);
		return_if_err(err);

		if (filc_test_may_share_leaf_by(f_ctx_src, fdr_src, 1) &&
		    filc_test_may_share_leaf_by(f_ctx_dst, fdr_dst, 0)) {
			err = filc_require_tree_by(f_ctx_dst, fdr_dst);
			return_if_err(err);

			err = filc_share_flnode_by(f_ctx_src, fdr_src,
			                           f_ctx_dst, fdr_dst);
			return_if_err(err);

		} else {
			err = filc_require_leaf(f_ctx_dst, fdr_dst);
			return_if_err(err);

			err = filc_require_mut_by(f_ctx_dst, fdr_dst);
			return_if_err(err);

			err = filc_copy_leaf_by(f_ctx_src, fdr_src, f_ctx_dst,
			                        fdr_dst, len);
			return_if_err(err);
		}
	} else if (fdr_src->has_data && fdr_dst->has_data) {
		err = filc_require_mut_by(f_ctx_dst, fdr_dst);
		return_if_err(err);

		err = filc_resolve_laddr_by(f_ctx_src, fdr_src);
		return_if_err(err);

		err = filc_resolve_laddr_by(f_ctx_dst, fdr_dst);
		return_if_err(err);

		if (filc_test_may_share_leaf_by(f_ctx_src, fdr_src, 1) &&
		    filc_test_may_share_leaf_by(f_ctx_dst, fdr_dst, 0)) {
			err = filc_discard_data_by(f_ctx_dst, fdr_dst);
			return_if_err(err);

			err = filc_share_flnode_by(f_ctx_src, fdr_src,
			                           f_ctx_dst, fdr_dst);
			return_if_err(err);

		} else {
			err = filc_copy_leaf_by(f_ctx_src, fdr_src, f_ctx_dst,
			                        fdr_dst, len);
			return_if_err(err);
		}
	} /* else: !fdr_src->has_data && !fdr_dst->has_data (no-op) */
	return 0;
}

static int filc_copy_range_iter(struct silofs_file_ctx *f_ctx_src,
                                struct silofs_file_ctx *f_ctx_dst)
{
	struct silofs_flnode_ref fdr_src;
	struct silofs_flnode_ref fdr_dst;
	size_t len;
	int err;

	while (filc_has_more_io(f_ctx_src) && filc_has_more_io(f_ctx_dst)) {
		err = filc_resolve_fpos(f_ctx_src, &fdr_src);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		err = filc_resolve_fpos(f_ctx_dst, &fdr_dst);
		if (err && (err != -SILOFS_ENOENT)) {
			return err;
		}
		len = filc_calc_next_copy_range_len(f_ctx_src, f_ctx_dst);
		if (!len) {
			break;
		}
		err = filc_copy_range_at_leaf_by(f_ctx_src, &fdr_src,
		                                 f_ctx_dst, &fdr_dst, len);
		return_if_err(err);

		filc_advance_by_nbytes(f_ctx_src, len);
		filc_advance_by_nbytes(f_ctx_dst, len);
	}
	return 0;
}

static int filc_check_copy_range_same(const struct silofs_file_ctx *f_ctx_src,
                                      const struct silofs_file_ctx *f_ctx_dst)
{
	const off_t src_off = f_ctx_src->off;
	const off_t src_end = silofs_off_end(src_off, f_ctx_src->len);
	const off_t dst_off = f_ctx_dst->off;
	const off_t dst_end = silofs_off_end(dst_off, f_ctx_dst->len);
	int ret;

	if (f_ctx_src->ii != f_ctx_dst->ii) {
		/* OK: not copy-range within same file */
		ret = 0;
	} else if (dst_end <= src_off) {
		/* OK: no overlap (pre) */
		ret = 0;
	} else if (src_end <= dst_off) {
		/* OK: no overlap (post) */
		ret = 0;
	} else {
		/* Don't allow overlapped copying within the same file. */
		ret = -SILOFS_EINVAL;
	}
	return ret;
}

static int filc_check_copy_range(const struct silofs_file_ctx *f_ctx_src,
                                 const struct silofs_file_ctx *f_ctx_dst)
{
	int err;

	err = filc_check_file_io(f_ctx_src);
	return_if_err(err);

	err = filc_check_file_io(f_ctx_dst);
	return_if_err(err);

	err = filc_check_copy_range_same(f_ctx_src, f_ctx_dst);
	return_if_err(err);

	return 0;
}

static int
filc_lseek_data_pos(const struct silofs_file_ctx *f_ctx, off_t *out_off)
{
	struct silofs_flnode_ref fdr = {
		.file_pos = -1,
	};
	struct silofs_file_ctx f_ctx_alt = {
		.op       = SILOFS_FILE_OP_LSEEK,
		.stg_mode = SILOFS_STG_CUR,
		.task     = f_ctx->task,
		.ii       = f_ctx->ii,
		.len      = 0,
		.beg      = f_ctx->beg,
		.off      = f_ctx->off,
		.end      = f_ctx->end,
		.whence   = SEEK_DATA,

	};
	int err;

	err = filc_lseek_data_leaf(&f_ctx_alt, &fdr);
	if (!err) {
		*out_off = fdr.file_pos;
	} else if (err == -SILOFS_ENOENT) {
		*out_off = SILOFS_FILE_SIZE_MAX;
		err      = 0;
	}
	return err;
}

static ssize_t min3(ssize_t a, ssize_t b, ssize_t c)
{
	return silofs_min_i64(silofs_min_i64(a, b), c);
}

static int filc_set_copy_range_start(struct silofs_file_ctx *f_ctx_src,
                                     struct silofs_file_ctx *f_ctx_dst)
{
	off_t off_data_src = 0, off_data_dst = 0;
	ssize_t skip_src = 0, skip_dst = 0, skip = 0;
	int err;

	err = filc_lseek_data_pos(f_ctx_src, &off_data_src);
	return_if_err(err);

	err = filc_lseek_data_pos(f_ctx_dst, &off_data_dst);
	return_if_err(err);

	if (f_ctx_src->off < off_data_src) {
		skip_src = silofs_off_len(f_ctx_src->off, off_data_src);
	}
	if (f_ctx_dst->off < off_data_dst) {
		skip_dst = silofs_off_len(f_ctx_dst->off, off_data_dst);
	}

	skip = min3(skip_src, skip_dst, SILOFS_COPY_FILE_RANGE_MAX);
	filc_advance_by_nbytes2(f_ctx_src, f_ctx_dst, skip);
	return 0;
}

static int filc_pre_copy_range(struct silofs_file_ctx *f_ctx_src,
                               struct silofs_file_ctx *f_ctx_dst)
{
	int err;

	err = filc_flush_dirty_now(f_ctx_src);
	return_if_err(err);

	err = filc_flush_dirty_now(f_ctx_dst);
	return_if_err(err);

	return 0;
}

static int filc_copy_range(struct silofs_file_ctx *f_ctx_src,
                           struct silofs_file_ctx *f_ctx_dst, size_t *out_ncp)
{
	int err;

	err = filc_check_copy_range(f_ctx_src, f_ctx_dst);
	return_if_err(err);

	err = filc_pre_copy_range(f_ctx_src, f_ctx_dst);
	return_if_err(err);

	err = filc_set_copy_range_start(f_ctx_src, f_ctx_dst);
	return_if_err(err);

	err = filc_copy_range_iter(f_ctx_src, f_ctx_dst);
	return_if_err(err);

	filc_update_post_io(f_ctx_dst);
	*out_ncp = filc_io_length(f_ctx_dst);

	return 0;
}

int silofs_do_copy_file_range(struct silofs_task_ctx *task,
                              struct silofs_inode_info *ii_in,
                              struct silofs_inode_info *ii_out, off_t off_in,
                              off_t off_out, size_t len, int flags,
                              size_t *out_ncp)
{
	struct silofs_file_ctx f_ctx_src = {
		.op           = SILOFS_FILE_OP_COPY_RANGE,
		.stg_mode     = SILOFS_STG_CUR,
		.task         = task,
		.ii           = ii_in,
		.len          = len,
		.beg          = off_in,
		.off          = off_in,
		.end          = ii_off_end(ii_in, off_in, len),
		.cp_flags     = flags,
		.with_backref = 0,
		.kill_suidgid = true,
	};
	struct silofs_file_ctx f_ctx_dst = {
		.op           = SILOFS_FILE_OP_COPY_RANGE,
		.stg_mode     = SILOFS_STG_COW,
		.task         = task,
		.ii           = ii_out,
		.len          = len,
		.beg          = off_out,
		.off          = off_out,
		.end          = silofs_off_end(off_out, len),
		.cp_flags     = flags,
		.with_backref = 0,
		.kill_suidgid = true,
	};
	int ret;

	*out_ncp = 0;
	filc_incref(&f_ctx_src);
	filc_incref(&f_ctx_dst);
	ret = filc_copy_range(&f_ctx_src, &f_ctx_dst, out_ncp);
	filc_decref(&f_ctx_dst);
	filc_decref(&f_ctx_src);

	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ii_setup_reg(struct silofs_inode_info *ii)
{
	struct silofs_inode_file *filin = ii_filin_of(ii);

	filin_setup(filin);
	silofs_ii_setdirty(ii);
}

int silofs_verify_ftree_node(const struct silofs_ftree_node *ftn)
{
	const off_t span    = (off_t)ftn_span(ftn);
	const size_t height = ftn_height(ftn);
	enum silofs_ltype child_ltype, expect_ltype;
	off_t spbh;
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
	if (ftn_isbottom(ftn) && (child_ltype != SILOFS_LTYPE_DATA64K)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}
