/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <dirent.h>
#include <errno.h>
#include <limits.h>

#define DTREE_FANOUT            SILOFS_DIR_NODE_NCHILDS
#define DTREE_DEPTH_MAX         SILOFS_DIR_TREE_DEPTH_MAX
#define DTREE_INDEX_MAX         SILOFS_DIR_TREE_INDEX_MAX
#define DTREE_INDEX_NULL        SILOFS_DIR_TREE_INDEX_NULL
#define DTREE_INDEX_ROOT        SILOFS_DIR_TREE_INDEX_ROOT


/*
 * TODO-0006: Support SILOFS_NAME_MAX=1023
 *
 * While 255 is de-facto standard for modern file-systems, long term vision
 * should allow more (think non-ascii with long UTF8 encoding).
 */
struct silofs_dir_entry_info {
	struct silofs_dnode_info       *dni;
	struct silofs_dir_entry        *de;
	struct silofs_ino_dt            ino_dt;
};

struct silofs_dir_ctx {
	const struct silofs_task       *task;
	struct silofs_sb_info          *sbi;
	struct silofs_inode_info       *dir_ii;
	struct silofs_inode_info       *parent_ii;
	struct silofs_inode_info       *child_ii;
	struct silofs_readdir_ctx      *rd_ctx;
	const struct silofs_qstr       *name;
	enum silofs_stage_mode          stg_mode;
	int keep_iter;
	int readdir_plus;
};

typedef unsigned int silofs_dtn_index_t;
typedef unsigned int silofs_dtn_ord_t;
typedef unsigned int silofs_dtn_depth_t;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t name_hash32_of(const struct silofs_qstr *name)
{
	return (uint32_t)(name->hash);
}

static bool ino_isvalid(ino_t ino)
{
	/* TODO: Check ino max */
	return (ino > SILOFS_INO_NULL);
}

static mode_t dttoif(mode_t dt)
{
	mode_t mode;

	switch (dt) {
	case DT_UNKNOWN:
	case DT_FIFO:
	case DT_CHR:
	case DT_DIR:
	case DT_BLK:
	case DT_REG:
	case DT_LNK:
	case DT_SOCK:
	case DT_WHT:
		mode = DTTOIF(dt);
		break;
	default:
		mode = 0;
		break;
	}
	return mode;
}

static void vaddr_of_dnode(struct silofs_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, SILOFS_STYPE_DTNODE, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool dtn_index_isnull(silofs_dtn_index_t dtn_index)
{
	return (dtn_index == DTREE_INDEX_NULL);
}

static bool dtn_index_isroot(silofs_dtn_index_t dtn_index)
{
	return (dtn_index == DTREE_INDEX_ROOT);
}

static bool dtn_index_isvalid(silofs_dtn_index_t dtn_index)
{
	return (dtn_index >= DTREE_INDEX_ROOT) &&
	       (dtn_index <= DTREE_INDEX_MAX);
}

static silofs_dtn_index_t dtn_index_to_parent(silofs_dtn_index_t dtn_index)
{
	silofs_dtn_index_t parent_index = DTREE_INDEX_NULL;

	if (!dtn_index_isroot(dtn_index)) {
		parent_index = ((dtn_index - 2) / DTREE_FANOUT) + 1;
	}
	return parent_index;
}

static silofs_dtn_ord_t dtn_index_to_child_ord(silofs_dtn_index_t dtn_index)
{
	const silofs_dtn_index_t parent_dtn_index =
	        dtn_index_to_parent(dtn_index);

	return (dtn_index - ((parent_dtn_index - 1) * DTREE_FANOUT) - 2);
}

static silofs_dtn_index_t
child_dtn_index_of(silofs_dtn_index_t parent_dtn_index,
                   silofs_dtn_ord_t child_ord)
{
	return ((parent_dtn_index - 1) * DTREE_FANOUT) + child_ord + 2;
}

static silofs_dtn_depth_t dtn_index_depth(silofs_dtn_index_t dtn_index)
{
	silofs_dtn_depth_t depth = 0;

	/* TODO: use shift operations */
	while (dtn_index > DTREE_INDEX_ROOT) {
		depth++;
		dtn_index = dtn_index_to_parent(dtn_index);
	}
	return depth;
}

static bool depth_isvalid(silofs_dtn_depth_t depth)
{
	return (depth <= DTREE_DEPTH_MAX);
}

static bool dtn_index_valid_depth(silofs_dtn_index_t dtn_index)
{
	silofs_dtn_depth_t depth;

	if (!dtn_index_isvalid(dtn_index)) {
		return false;
	}
	depth = dtn_index_depth(dtn_index);
	if (!depth_isvalid(depth)) {
		return false;
	}
	return true;
}

static silofs_dtn_ord_t
hash_to_child_ord(uint64_t hash, silofs_dtn_depth_t depth)
{
	silofs_assert_gt(depth, 0);
	silofs_assert_lt(depth, sizeof(hash));
	silofs_assert_le(depth, DTREE_DEPTH_MAX);

	return (hash >> (8 * (depth - 1))) % DTREE_FANOUT;
}

static silofs_dtn_index_t
hash_to_child_dtn_index(uint64_t hash, silofs_dtn_index_t parent_dtn_index)
{
	const silofs_dtn_depth_t depth = dtn_index_depth(parent_dtn_index);
	const silofs_dtn_ord_t child_ord = hash_to_child_ord(hash, depth + 1);

	return child_dtn_index_of(parent_dtn_index, child_ord);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define DOFF_SHIFT 14

static void
encode_doffset(uint64_t dtn_index, uint64_t slot, uint64_t *out_doff)
{
	const uint64_t mask = (1L << DOFF_SHIFT) - 1;

	*out_doff = (dtn_index << DOFF_SHIFT) | (slot & mask);
}

static void
decode_doffset(uint64_t doff, uint64_t *out_dtn_index, uint64_t *out_slot)
{
	const uint64_t mask = (1L << DOFF_SHIFT) - 1;

	*out_dtn_index = (doff >> DOFF_SHIFT);
	*out_slot = (doff & mask);
}

static loff_t make_doffset(size_t dtn_index, size_t slot)
{
	uint64_t doff;

	STATICASSERT_LT(SILOFS_DIR_NODE_NENTS, 1 << 10);
	STATICASSERT_LE(SILOFS_DIR_NODE_SIZE, 1 << DOFF_SHIFT);

	encode_doffset(dtn_index, slot, &doff);
	return (loff_t)((doff << 2) | 2);
}

static silofs_dtn_index_t doff_to_dtn_index(loff_t doff)
{
	uint64_t dtn_index;
	uint64_t slot;

	decode_doffset((uint64_t)(doff >> 2), &dtn_index, &slot);
	return (dtn_index <= DTREE_INDEX_MAX) ?
	       (silofs_dtn_index_t)dtn_index : DTREE_INDEX_NULL;
}

static size_t doff_to_slot(loff_t doff)
{
	uint64_t dtn_index;
	uint64_t slot;

	decode_doffset((uint64_t)(doff >> 2), &dtn_index, &slot);
	return slot;
}

static loff_t calc_d_isize(silofs_dtn_index_t dtn_index_last)
{
	loff_t dir_isize;

	if (dtn_index_isnull(dtn_index_last)) {
		dir_isize = SILOFS_DIR_EMPTY_SIZE;
	} else {
		dir_isize = make_doffset(dtn_index_last + 1, 0) & ~3;
	}
	return dir_isize;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dir_entry *de_unconst(const struct silofs_dir_entry *de)
{
	union {
		const struct silofs_dir_entry *p;
		struct silofs_dir_entry *q;
	} u = {
		.p = de
	};
	return u.q;
}

static ino_t de_ino(const struct silofs_dir_entry *de)
{
	return silofs_ino_to_cpu(de->de_ino);
}

static void de_set_ino(struct silofs_dir_entry *de, ino_t ino)
{
	de->de_ino = silofs_cpu_to_ino(ino);
}

static uint32_t de_name_hash(const struct silofs_dir_entry *de)
{
	return silofs_le32_to_cpu(de->de_name_hash);
}

static void de_set_name_hash(struct silofs_dir_entry *de, uint32_t hash)
{
	de->de_name_hash = silofs_cpu_to_le32(hash);
}

static mode_t de_dt(const struct silofs_dir_entry *de)
{
	const uint64_t name_len_dt =
	        silofs_le16_to_cpu(de->de_name_len_dt);

	return (mode_t)(name_len_dt & 0x3F);
}

static size_t de_name_len(const struct silofs_dir_entry *de)
{
	const uint64_t name_len_dt =
	        silofs_le16_to_cpu(de->de_name_len_dt);

	return (size_t)(name_len_dt >> 6);
}

static void de_set_name_len_dt(struct silofs_dir_entry *de,
                               size_t name_len, mode_t dt)
{
	const uint64_t name_len_dt =
	        ((uint64_t)name_len << 6) | ((uint64_t)dt & 0x3F);

	de->de_name_len_dt = silofs_cpu_to_le16((uint16_t)name_len_dt);
}

static size_t de_name_pos(const struct silofs_dir_entry *de)
{
	return silofs_le16_to_cpu(de->de_name_pos);
}

static void de_set_name_pos(struct silofs_dir_entry *de, size_t pos)
{
	de->de_name_pos = silofs_cpu_to_le16((uint16_t)pos);
}

static bool de_has_name_len(const struct silofs_dir_entry *de, size_t nlen)
{
	return (de_name_len(de) == nlen);
}

static bool de_has_name_hash(const struct silofs_dir_entry *de, uint32_t hash)
{
	return (de_name_hash(de) == hash);
}

static size_t de_data_size_of(const struct silofs_dir_entry *de, size_t nlen)
{
	return sizeof(*de) + nlen;
}

static void de_assign_meta(struct silofs_dir_entry *de, ino_t ino, mode_t dt,
                           uint32_t hash, size_t name_len, size_t name_pos)
{
	de_set_ino(de, ino);
	de_set_name_hash(de, hash);
	de_set_name_len_dt(de, name_len, dt);
	de_set_name_pos(de, name_pos);
}

static bool de_isactive(const struct silofs_dir_entry *de)
{
	return ino_isvalid(de_ino(de)) && (de_name_len(de) > 0);
}

static void de_deactivate(struct silofs_dir_entry *de)
{
	de_set_ino(de, SILOFS_INO_NULL);
	de_set_name_len_dt(de, 0, 0);
	de_set_name_pos(de, 0);
}

static bool de_isvalid(const struct silofs_dir_entry *de)
{
	ino_t ino;
	mode_t dt;
	size_t name_len;
	size_t name_pos;

	ino = de_ino(de);
	if (!ino_isvalid(ino)) {
		return false;
	}
	dt = de_dt(de);
	if (dttoif(dt) == 0) {
		return false;
	}
	name_len = de_name_len(de);
	if (!name_len || (name_len > SILOFS_NAME_MAX)) {
		return false;
	}
	name_pos = de_name_pos(de);
	if (!name_pos || (name_pos >= SILOFS_DIR_NODE_NBUF_SIZE)) {
		return false;
	}
	return true;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t dtn_ino(const struct silofs_dtree_node *dtn)
{
	return silofs_ino_to_cpu(dtn->dn_ino);
}

static void dtn_set_ino(struct silofs_dtree_node *dtn, ino_t ino)
{
	dtn->dn_ino = silofs_cpu_to_ino(ino);
}

static loff_t dtn_parent(const struct silofs_dtree_node *dtn)
{
	return silofs_off_to_cpu(dtn->dn_parent);
}

static void dtn_set_parent(struct silofs_dtree_node *dtn, loff_t parent)
{
	dtn->dn_parent = silofs_cpu_to_off(parent);
}

static silofs_dtn_index_t dtn_node_index(const struct silofs_dtree_node *dtn)
{
	return silofs_le32_to_cpu(dtn->dn_node_index);
}

static void dtn_set_node_index(struct silofs_dtree_node *dtn,
                               silofs_dtn_index_t index)
{
	dtn->dn_node_index = silofs_cpu_to_le32((uint32_t)index);
}

static size_t dtn_data_max(const struct silofs_dtree_node *dtn)
{
	return sizeof(dtn->dn_data);
}

static size_t dtn_nde(const struct silofs_dtree_node *dtn)
{
	return silofs_le16_to_cpu(dtn->dn_nde);
}

static void dtn_set_nde(struct silofs_dtree_node *dtn, size_t cnt)
{
	silofs_assert_le(cnt, ARRAY_SIZE(dtn->dn_data.de));
	dtn->dn_nde = silofs_cpu_to_le16((uint16_t)cnt);
}

static void dtn_inc_nde(struct silofs_dtree_node *dtn)
{
	dtn_set_nde(dtn, dtn_nde(dtn) + 1);
}

static void dtn_dec_nde(struct silofs_dtree_node *dtn)
{
	dtn_set_nde(dtn, dtn_nde(dtn) - 1);
}

static size_t dtn_nnb(const struct silofs_dtree_node *dtn)
{
	return silofs_le16_to_cpu(dtn->dn_nnb);
}

static void dtn_set_nnb(struct silofs_dtree_node *dtn, size_t nb)
{
	silofs_assert_le(nb, sizeof(dtn->dn_data));
	dtn->dn_nnb = silofs_cpu_to_le16((uint16_t)nb);
}

static void dtn_add_nnb(struct silofs_dtree_node *dtn, size_t nb)
{
	dtn_set_nnb(dtn, dtn_nnb(dtn) + nb);
}

static void dtn_sub_nnb(struct silofs_dtree_node *dtn, size_t nb)
{
	dtn_set_nnb(dtn, dtn_nnb(dtn) - nb);
}

static size_t dtn_data_used(const struct silofs_dtree_node *dtn)
{
	return dtn_nnb(dtn) + (dtn_nde(dtn) * sizeof(dtn->dn_data.de[0]));
}

static void dtn_reset_data(struct silofs_dtree_node *dtn)
{
	silofs_memzero(&dtn->dn_data, sizeof(dtn->dn_data));
}

static loff_t dtn_child_off(const struct silofs_dtree_node *dtn,
                            silofs_dtn_ord_t ord)
{
	return silofs_vaddr56_parse(&dtn->dn_child[ord]);
}

static void dtn_child(const struct silofs_dtree_node *dtn,
                      silofs_dtn_ord_t ord, struct silofs_vaddr *out_vaddr)
{
	vaddr_setup(out_vaddr, SILOFS_STYPE_DTNODE, dtn_child_off(dtn, ord));
}

static void dtn_set_child(struct silofs_dtree_node *dtn, silofs_dtn_ord_t ord,
                          const struct silofs_vaddr *vaddr)
{
	silofs_vaddr56_set(&dtn->dn_child[ord], vaddr->off);
}

static void dtn_reset_childs(struct silofs_dtree_node *dtn)
{
	silofs_dtn_ord_t ord;

	for (ord = 0; ord < ARRAY_SIZE(dtn->dn_child); ++ord) {
		dtn_set_child(dtn, ord, vaddr_none());
	}
}

static void dtn_setup(struct silofs_dtree_node *dtn, ino_t ino,
                      silofs_dtn_index_t dtn_index, loff_t parent_off)
{
	silofs_assert_le(dtn_index, DTREE_INDEX_MAX);

	dtn_set_ino(dtn, ino);
	dtn_set_parent(dtn, parent_off);
	dtn_set_node_index(dtn, dtn_index);
	dtn_set_nde(dtn, 0);
	dtn_set_nnb(dtn, 0);
	dtn_reset_childs(dtn);
	dtn_reset_data(dtn);
}

static silofs_dtn_ord_t dtn_child_ord(const struct silofs_dtree_node *dtn)
{
	return dtn_index_to_child_ord(dtn_node_index(dtn));
}

static silofs_dtn_depth_t dtn_depth(const struct silofs_dtree_node *dtn)
{
	const silofs_dtn_index_t dtn_index = dtn_node_index(dtn);

	return dtn_index_depth(dtn_index);
}

static struct silofs_dir_entry *
dtn_de_begin(const struct silofs_dtree_node *dtn)
{
	return de_unconst(&dtn->dn_data.de[0]);
}

static struct silofs_dir_entry *
dtn_de_end(const struct silofs_dtree_node *dtn)
{
	return dtn_de_begin(dtn) + dtn_nde(dtn);
}

static char *dtn_name_at(const struct silofs_dtree_node *dtn, size_t name_pos)
{
	const void *dat = &dtn->dn_data.nb[name_pos];

	silofs_assert_gt(name_pos, 0);
	silofs_assert_le(name_pos, ARRAY_SIZE(dtn->dn_data.nb));
	return unconst(dat);
}

static char *dtn_names_beg(const struct silofs_dtree_node *dtn)
{
	const size_t nnb = dtn_nnb(dtn);

	silofs_assert_lt(nnb, ARRAY_SIZE(dtn->dn_data.nb));
	return dtn_name_at(dtn, ARRAY_SIZE(dtn->dn_data.nb) - nnb);
}

static char *dtn_names_end(const struct silofs_dtree_node *dtn)
{
	return dtn_name_at(dtn, ARRAY_SIZE(dtn->dn_data.nb));
}

static char *dtn_name_of(const struct silofs_dtree_node *dtn,
                         const struct silofs_dir_entry *de)
{
	const size_t name_pos = de_name_pos(de);
	const char *name = dtn_name_at(dtn, name_pos);

	return unconst(name);
}

static bool dtn_has_name_at(const struct silofs_dtree_node *dtn,
                            const struct silofs_dir_entry *de,
                            const struct silofs_qstr *name)
{
	const char *de_name = dtn_name_of(dtn, de);

	return memcmp(de_name, name->s.str, name->s.len) == 0;
}

static bool dtn_de_has_name(const struct silofs_dtree_node *dtn,
                            const struct silofs_dir_entry *de,
                            const struct silofs_qstr *name)
{
	const uint32_t name_hash32 = name_hash32_of(name);

	if (!de_has_name_hash(de, name_hash32)) {
		return false;
	}
	if (!de_has_name_len(de, name->s.len)) {
		return false;
	}
	if (!dtn_has_name_at(dtn, de, name)) {
		return false;
	}
	return true;
}

static const struct silofs_dir_entry *
dtn_search(const struct silofs_dtree_node *dtn,
           const struct silofs_qstr *name)
{
	const struct silofs_dir_entry *de;
	const struct silofs_dir_entry *de_beg = dtn_de_begin(dtn);
	const struct silofs_dir_entry *de_end = dtn_de_end(dtn);

	for (de = de_beg; de < de_end; ++de) {
		if (de_isactive(de) &&
		    dtn_de_has_name(dtn, de, name)) {
			return de;
		}
	}
	return NULL;
}

static size_t dtn_slot_of(const struct silofs_dtree_node *dtn,
                          const struct silofs_dir_entry *de)
{
	const struct silofs_dir_entry *de_base = dtn_de_begin(dtn);

	return (size_t)(de - de_base);
}

static loff_t dtn_doffset_of(const struct silofs_dtree_node *dtn,
                             const struct silofs_dir_entry *de)
{
	const size_t dtn_index = dtn_node_index(dtn);
	const size_t slot = dtn_slot_of(dtn, de);

	return make_doffset(dtn_index, slot);
}

static const struct silofs_dir_entry *
dtn_de_at_slot(const struct silofs_dtree_node *dtn, size_t slot)
{
	const size_t nde = dtn_nde(dtn);

	silofs_assert_le(slot, ARRAY_SIZE(dtn->dn_data.de));
	return (slot < nde) ? &dtn->dn_data.de[slot] : dtn_de_end(dtn);
}

static const struct silofs_dir_entry *
dtn_scan(const struct silofs_dtree_node *dtn, loff_t pos)
{
	const size_t slot = doff_to_slot(pos);
	const struct silofs_dir_entry *de_from = dtn_de_at_slot(dtn, slot);
	const struct silofs_dir_entry *de_end = dtn_de_end(dtn);
	const struct silofs_dir_entry *de = NULL;
	loff_t doff;

	for (de = de_from; de < de_end; ++de) {
		if (!de_isactive(de)) {
			continue;
		}
		doff = dtn_doffset_of(dtn, de);
		if (doff >= pos) {
			return de;
		}
	}
	return NULL;
}

static bool dtn_may_insert(const struct silofs_dtree_node *dtn, size_t nlen)
{
	const size_t nwant = de_data_size_of(dtn->dn_data.de, nlen);
	const size_t nused = dtn_data_used(dtn);
	const size_t limit = dtn_data_max(dtn);

	silofs_assert_le(nused, limit);
	return (nwant + nused) <= limit;
}

static void dtn_de_assing_name(struct silofs_dtree_node *dtn,
                               const struct silofs_dir_entry *de,
                               const struct silofs_qstr *name)
{
	char *dst = dtn_name_of(dtn, de);

	memcpy(dst, name->s.str, name->s.len);
}

static size_t dtn_insert_name_pos(struct silofs_dtree_node *dtn, size_t nlen)
{
	const size_t nnb = dtn_nnb(dtn);

	silofs_assert_lt(nnb + nlen, sizeof(dtn->dn_data.nb));

	return sizeof(dtn->dn_data.nb) - nnb - nlen;
}

static struct silofs_dir_entry *
dtn_resolve_insert_de(struct silofs_dtree_node *dtn)
{
	struct silofs_dir_entry *de;
	struct silofs_dir_entry *de_beg = dtn_de_begin(dtn);
	struct silofs_dir_entry *de_end = dtn_de_end(dtn);

	for (de = de_beg; de < de_end; ++de) {
		if (!de_isactive(de)) {
			return de;
		}
	}
	return de_end;
}

static void dtn_insert(struct silofs_dtree_node *dtn,
                       const struct silofs_qstr *name, ino_t ino, mode_t dt)
{
	struct silofs_dir_entry *de;
	const size_t name_len = name->s.len;
	const size_t name_pos = dtn_insert_name_pos(dtn, name_len);
	const uint32_t name_hash32 = name_hash32_of(name);

	de = dtn_resolve_insert_de(dtn);
	de_assign_meta(de, ino, dt, name_hash32, name_len, name_pos);
	dtn_de_assing_name(dtn, de, name);

	if (de == dtn_de_end(dtn)) {
		dtn_inc_nde(dtn);
	}
	dtn_add_nnb(dtn, name_len);
}

static void dtn_punch_name_at(struct silofs_dtree_node *dtn,
                              size_t name_pos, size_t name_len)
{
	char *beg = dtn_names_beg(dtn);
	char *name = dtn_name_at(dtn, name_pos);
	const size_t cnt = (size_t)(name - beg);

	silofs_assert_ge(name, beg);
	memmove((name + name_len) - cnt, beg, cnt);
}

static void dtn_punch_de_name(struct silofs_dtree_node *dtn,
                              const struct silofs_dir_entry *de)
{
	const size_t name_len = de_name_len(de);
	const size_t name_pos = de_name_pos(de);

	dtn_punch_name_at(dtn, name_pos, name_len);
}

static void dtn_remove_fixup(struct silofs_dtree_node *dtn,
                             size_t name_pos_ref, size_t nb_moved)
{
	struct silofs_dir_entry *de;
	struct silofs_dir_entry *de_beg = dtn_de_begin(dtn);
	const struct silofs_dir_entry *de_end = dtn_de_end(dtn);
	size_t name_pos;

	for (de = de_beg; de < de_end; ++de) {
		if (!de_isactive(de)) {
			continue;
		}
		name_pos = de_name_pos(de);
		if (name_pos >= name_pos_ref) {
			continue;
		}
		de_set_name_pos(de, name_pos + nb_moved);
	}
}

static void dtn_trim_nonactive_des(struct silofs_dtree_node *dtn)
{
	struct silofs_dir_entry *de_end;
	struct silofs_dir_entry *de;

	for (size_t nde = dtn_nde(dtn); nde > 0; --nde) {
		de_end = dtn_de_end(dtn);
		de = de_end - 1;
		if (de_isactive(de)) {
			break;
		}
		dtn_dec_nde(dtn);
	}
}

static void dtn_remove(struct silofs_dtree_node *dtn,
                       struct silofs_dir_entry *de)
{
	const size_t name_len = de_name_len(de);
	const size_t name_pos = de_name_pos(de);

	dtn_punch_de_name(dtn, de);
	de_deactivate(de);

	dtn_sub_nnb(dtn, name_len);
	dtn_remove_fixup(dtn, name_pos, name_len);
	dtn_trim_nonactive_des(dtn);
}

static loff_t dtn_next_doffset(const struct silofs_dtree_node *dtn)
{
	const size_t dtn_index = dtn_node_index(dtn);

	return make_doffset(dtn_index + 1, 0);
}

static void dtn_child_by_ord(const struct silofs_dtree_node *dtn,
                             silofs_dtn_ord_t ord,
                             struct silofs_vaddr *out_vaddr)
{
	dtn_child(dtn, ord, out_vaddr);
}

static void dtn_child_by_hash(const struct silofs_dtree_node *dtn,
                              uint64_t hash, struct silofs_vaddr *out_vaddr)
{
	silofs_dtn_ord_t ord;
	const silofs_dtn_depth_t depth = dtn_depth(dtn);

	ord = hash_to_child_ord(hash, depth + 1);
	dtn_child_by_ord(dtn, ord, out_vaddr);
}

static void dtn_parent_addr(const struct silofs_dtree_node *dtn,
                            struct silofs_vaddr *out_vaddr)
{
	vaddr_of_dnode(out_vaddr, dtn_parent(dtn));
}

static int dtn_verify_des(const struct silofs_dtree_node *dtn)
{
	const struct silofs_dir_entry *de;
	const struct silofs_dir_entry *de_beg = dtn_de_begin(dtn);
	const struct silofs_dir_entry *de_end = dtn_de_end(dtn);

	for (de = de_beg; de < de_end; ++de) {
		if (de_isactive(de) && !de_isvalid(de)) {
			return -SILOFS_EFSCORRUPTED;
		}
	}
	return 0;
}

static int dtn_verify_names(const struct silofs_dtree_node *dtn)
{
	const char *chr = dtn_names_beg(dtn);
	const char *end = dtn_names_end(dtn);

	while (chr < end) {
		if ((*chr == 0) || (*chr == '/')) {
			return -SILOFS_EFSCORRUPTED;
		}
		chr++;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dnode_info *
dni_unconst(const struct silofs_dnode_info *dni)
{
	union {
		const struct silofs_dnode_info *p;
		struct silofs_dnode_info *q;
	} u = {
		.p = dni
	};
	return u.q;
}

static void dni_dirtify(struct silofs_dnode_info *dni)
{
	vi_dirtify(&dni->dn_vi);
}

static void dni_incref(struct silofs_dnode_info *dni)
{
	if (likely(dni != NULL)) {
		vi_incref(&dni->dn_vi);
	}
}

static void dni_decref(struct silofs_dnode_info *dni)
{
	if (likely(dni != NULL)) {
		vi_decref(&dni->dn_vi);
	}
}

static const struct silofs_vaddr *
dni_vaddr(const struct silofs_dnode_info *dni)
{
	return vi_vaddr(&dni->dn_vi);
}

static void
dni_child_addr_by_hash(const struct silofs_dnode_info *dni,
                       uint64_t hash, struct silofs_vaddr *out_vaddr)
{
	dtn_child_by_hash(dni->dtn, hash, out_vaddr);
}

static void
dni_child_addr_by_ord(const struct silofs_dnode_info *dni,
                      silofs_dtn_ord_t ord, struct silofs_vaddr *out_vaddr)
{
	dtn_child_by_ord(dni->dtn, ord, out_vaddr);
}

static void dni_setup_dnode(struct silofs_dnode_info *dni, ino_t ino,
                            const struct silofs_vaddr *parent,
                            silofs_dtn_index_t dtn_index)
{
	dtn_setup(dni->dtn, ino, dtn_index, parent->off);
}

static int
dni_check_child_depth(const struct silofs_dnode_info *dni,
                      silofs_dtn_depth_t parent_depth)
{
	const struct silofs_vaddr *vaddr = dni_vaddr(dni);
	const silofs_dtn_depth_t child_depth = dtn_depth(dni->dtn);
	int err = 0;

	if ((parent_depth + 1) != child_depth) {
		log_err("illegal-tree-depth: voff=0x%lx "
		        "parent_depth=%u child_depth=%u ",
		        vaddr->off, parent_depth, child_depth);
		err = -SILOFS_EFSCORRUPTED;
	}
	return err;
}

static void dni_bind_child_at(struct silofs_dnode_info *parent_dni,
                              const struct silofs_vaddr *vaddr,
                              silofs_dtn_index_t dtn_index)
{
	const silofs_dtn_ord_t child_ord = dtn_index_to_child_ord(dtn_index);

	dtn_set_child(parent_dni->dtn, child_ord, vaddr);
	dni_dirtify(parent_dni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dei_setup(struct silofs_dir_entry_info *dei,
                      const struct silofs_dnode_info *dni,
                      const struct silofs_dir_entry *de)
{
	dei->dni = dni_unconst(dni);
	dei->de = unconst(de);
	dei->ino_dt.ino = de_ino(de);
	dei->ino_dt.dt = de_dt(de);
}

static mode_t ii_dtype_of(const struct silofs_inode_info *ii)
{
	return IFTODT(ii_mode(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_dir *idr_of(const struct silofs_inode *inode)
{
	struct silofs_inode *dir_inode = unconst(inode);

	return &dir_inode->i_sp.d;
}

static uint64_t idr_seed(const struct silofs_inode_dir *idr)
{
	return silofs_le64_to_cpu(idr->d_seed);
}

static void idr_set_seed(struct silofs_inode_dir *idr, size_t seed)
{
	idr->d_seed = silofs_cpu_to_le64(seed);
}

static uint64_t idr_ndents(const struct silofs_inode_dir *idr)
{
	return silofs_le64_to_cpu(idr->d_ndents);
}

static void idr_set_ndents(struct silofs_inode_dir *idr, size_t n)
{
	idr->d_ndents = silofs_cpu_to_le64(n);
}

static void idr_inc_ndents(struct silofs_inode_dir *idr)
{
	idr_set_ndents(idr, idr_ndents(idr) + 1);
}

static void idr_dec_ndents(struct silofs_inode_dir *idr)
{
	idr_set_ndents(idr, idr_ndents(idr) - 1);
}

static silofs_dtn_index_t idr_last_index(const struct silofs_inode_dir *idr)
{
	return silofs_le32_to_cpu(idr->d_last_index);
}

static void idr_set_last_index(struct silofs_inode_dir *idr, size_t index)
{
	idr->d_last_index = silofs_cpu_to_le32((uint32_t)index);
}

static void idr_update_last_index(struct silofs_inode_dir *idr,
                                  silofs_dtn_index_t alt_index, bool add)
{
	silofs_dtn_index_t new_index;
	const silofs_dtn_index_t cur_index = idr_last_index(idr);
	const silofs_dtn_index_t nil_index = DTREE_INDEX_NULL;

	new_index = cur_index;
	if (add) {
		if ((cur_index < alt_index) || dtn_index_isnull(cur_index)) {
			new_index = alt_index;
		}
	} else {
		if (cur_index == alt_index) {
			new_index = !cur_index ? nil_index : cur_index - 1;
		}
	}
	idr_set_last_index(idr, new_index);
}

static loff_t idr_htree_root(const struct silofs_inode_dir *idr)
{
	return silofs_off_to_cpu(idr->d_root);
}

static void idr_set_htree_root(struct silofs_inode_dir *idr, loff_t off)
{
	idr->d_root = silofs_cpu_to_off(off);
}

static enum silofs_dirf idr_flags(const struct silofs_inode_dir *idr)
{
	return silofs_le32_to_cpu(idr->d_flags);
}

static void idr_set_flags(struct silofs_inode_dir *idr,
                          enum silofs_dirf flags)
{
	idr->d_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static enum silofs_dirhfn idr_hashfn(const struct silofs_inode_dir *idr)
{
	return (enum silofs_dirhfn)(idr->d_hashfn);
}

static void idr_set_hashfn(struct silofs_inode_dir *idr,
                           enum silofs_dirhfn hfn)
{
	idr->d_hashfn = (uint8_t)hfn;
}

static void idr_setup(struct silofs_inode_dir *idr, uint64_t seed)
{
	idr_set_seed(idr, seed);
	idr_set_htree_root(idr, SILOFS_OFF_NULL);
	idr_set_last_index(idr, DTREE_INDEX_NULL);
	idr_set_ndents(idr, 0);
	idr_set_flags(idr, SILOFS_DIRF_NAME_UTF8);
	idr_set_hashfn(idr, SILOFS_DIRHASH_XXH64);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_dir *
dir_ispec_of(const struct silofs_inode_info *dir_ii)
{
	return idr_of(dir_ii->inode);
}

static uint64_t dir_ndents(const struct silofs_inode_info *dir_ii)
{
	return idr_ndents(dir_ispec_of(dir_ii));
}

static void dir_inc_ndents(struct silofs_inode_info *dir_ii)
{
	idr_inc_ndents(dir_ispec_of(dir_ii));
	ii_dirtify(dir_ii);
}

static void dir_dec_ndents(struct silofs_inode_info *dir_ii)
{
	idr_dec_ndents(dir_ispec_of(dir_ii));
	ii_dirtify(dir_ii);
}

static loff_t dir_htree_root(const struct silofs_inode_info *dir_ii)
{
	return idr_htree_root(dir_ispec_of(dir_ii));
}

static void dir_htree_root_addr(const struct silofs_inode_info *dir_ii,
                                struct silofs_vaddr *out_vaddr)
{
	vaddr_of_dnode(out_vaddr, dir_htree_root(dir_ii));
}

static bool dir_has_htree(const struct silofs_inode_info *dir_ii)
{
	return !off_isnull(dir_htree_root(dir_ii));
}

static void dir_set_htree_root(struct silofs_inode_info *dir_ii,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_dir *idr = dir_ispec_of(dir_ii);

	idr_set_htree_root(idr, vaddr->off);
	idr_set_last_index(idr, DTREE_INDEX_ROOT);
}

static silofs_dtn_index_t
dir_last_index(const struct silofs_inode_info *dir_ii)
{
	return idr_last_index(dir_ispec_of(dir_ii));
}

static void dir_update_last_index(struct silofs_inode_info *dir_ii,
                                  silofs_dtn_index_t alt_index, bool add)
{
	idr_update_last_index(dir_ispec_of(dir_ii), alt_index, add);
}

size_t silofs_dir_ndentries(const struct silofs_inode_info *dir_ii)
{
	return dir_ndents(dir_ii);
}

uint64_t silofs_dir_seed(const struct silofs_inode_info *dir_ii)
{
	return idr_seed(dir_ispec_of(dir_ii));
}

enum silofs_dirf silofs_dir_flags(const struct silofs_inode_info *dir_ii)
{
	return idr_flags(dir_ispec_of(dir_ii));
}

enum silofs_dirhfn silofs_dir_hfn(const struct silofs_inode_info *dir_ii)
{
	return idr_hashfn(dir_ispec_of(dir_ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t unique_seed(void)
{
	uint64_t s;

	silofs_getentropy(&s, sizeof(s));
	return s ^ (uint64_t)silofs_time_now();
}

void silofs_setup_dir(struct silofs_inode_info *dir_ii,
                      mode_t parent_mode, nlink_t nlink)
{
	struct silofs_iattr iattr = {
		.ia_size = SILOFS_DIR_EMPTY_SIZE,
		.ia_nlink = nlink,
		.ia_blocks = 0,
		.ia_mode = ii_mode(dir_ii) | (parent_mode & S_ISGID),
		.ia_flags =
		SILOFS_IATTR_SIZE | SILOFS_IATTR_BLOCKS |
		SILOFS_IATTR_NLINK | SILOFS_IATTR_MODE
	};

	idr_setup(idr_of(dir_ii->inode), unique_seed());
	ii_update_iattrs(dir_ii, NULL, &iattr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int search_dnode(const struct silofs_dnode_info *dni,
                        const struct silofs_qstr *name,
                        struct silofs_dir_entry_info *out_dei)
{
	const struct silofs_dir_entry *de;

	de = dtn_search(dni->dtn, name);
	if (de == NULL) {
		return -ENOENT;
	}
	dei_setup(out_dei, dni, de);
	return 0;
}

static int dic_recheck_dnode(const struct silofs_dir_ctx *d_ctx,
                             struct silofs_dnode_info *dni)
{
	ino_t h_ino;
	ino_t d_ino;

	if (dni->dn_vi.v_recheck) {
		return 0;
	}
	h_ino = dtn_ino(dni->dtn);
	d_ino = ii_ino(d_ctx->dir_ii);

	/* TODO: not a clean logic, improve me */
	if ((h_ino != d_ino) && (d_ino == SILOFS_INO_ROOT)) {
		d_ino = silofs_ii_ino_of(d_ctx->dir_ii);
	}
	if (h_ino != d_ino) {
		log_err("bad dnode: h_ino=%lu d_ino=%lu", h_ino, d_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	dni->dn_vi.v_recheck = true;
	return 0;
}

static int dic_stage_dnode(const struct silofs_dir_ctx *d_ctx,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_dnode_info **out_dni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_dnode_info *dni = NULL;
	int ret;

	ii_incref(d_ctx->dir_ii);
	ret = silofs_stage_vnode(d_ctx->task, vaddr, d_ctx->stg_mode,
	                         ii_ino(d_ctx->dir_ii), &vi);
	if (ret) {
		goto out;
	}
	dni = silofs_dni_from_vi(vi);
	silofs_dni_rebind_view(dni);
	ret = dic_recheck_dnode(d_ctx, dni);
	if (ret) {
		goto out;
	}
	*out_dni = dni;
out:
	ii_decref(d_ctx->dir_ii);
	return ret;
}

static int dic_stage_child(const struct silofs_dir_ctx *d_ctx,
                           struct silofs_dnode_info *parent_dni,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_dnode_info **out_dni)
{
	int ret;

	dni_incref(parent_dni);
	ret = dic_stage_dnode(d_ctx, vaddr, out_dni);
	dni_decref(parent_dni);
	return ret;
}

static int
dic_stage_child_by_name(const struct silofs_dir_ctx *d_ctx,
                        struct silofs_dnode_info *parent_dni,
                        struct silofs_dnode_info **out_dni)
{
	struct silofs_vaddr vaddr;

	dni_child_addr_by_hash(parent_dni, d_ctx->name->hash, &vaddr);
	return dic_stage_child(d_ctx, parent_dni, &vaddr, out_dni);
}

static int dic_spawn_dnode(const struct silofs_dir_ctx *d_ctx,
                           struct silofs_dnode_info **out_dni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_dnode_info *dni = NULL;
	int err;

	err = silofs_spawn_vnode(d_ctx->task, SILOFS_STYPE_DTNODE,
	                         ii_ino(d_ctx->dir_ii), &vi);
	if (err) {
		return err;
	}
	dni = silofs_dni_from_vi(vi);
	silofs_dni_rebind_view(dni);
	*out_dni = dni;
	return 0;
}

static int dic_remove_dnode(const struct silofs_dir_ctx *d_ctx,
                            struct silofs_dnode_info *dni)
{
	return silofs_remove_vnode(d_ctx->task, &dni->dn_vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static silofs_dtn_index_t
dic_last_node_index_of(const struct silofs_dir_ctx *d_ctx)
{
	return dir_last_index(d_ctx->dir_ii);
}

static silofs_dtn_index_t
dic_curr_node_index_of(const struct silofs_dir_ctx *d_ctx)
{
	return doff_to_dtn_index(d_ctx->rd_ctx->pos);
}

static void dic_update_isizeblocks(const struct silofs_dir_ctx *d_ctx,
                                   silofs_dtn_index_t dtn_index, bool new_node)
{
	silofs_dtn_index_t last_dtn_index;
	const long dif = new_node ? 1 : -1;
	struct silofs_inode_info *dir_ii = d_ctx->dir_ii;
	const struct silofs_creds *creds = &d_ctx->task->t_oper.op_creds;

	dir_update_last_index(dir_ii, dtn_index, new_node);
	last_dtn_index = dir_last_index(dir_ii);

	ii_update_isize(dir_ii, creds, calc_d_isize(last_dtn_index));
	ii_update_iblocks(dir_ii, creds, SILOFS_STYPE_DTNODE, dif);
}

static int dic_spawn_setup_dnode(const struct silofs_dir_ctx *d_ctx,
                                 const struct silofs_vaddr *parent,
                                 silofs_dtn_index_t dtn_index,
                                 struct silofs_dnode_info **out_dni)
{
	struct silofs_inode_info *dir_ii = d_ctx->dir_ii;
	int err;

	err = dic_spawn_dnode(d_ctx, out_dni);
	if (err) {
		return err;
	}
	dni_setup_dnode(*out_dni, ii_ino(dir_ii), parent, dtn_index);
	dni_dirtify(*out_dni);

	dic_update_isizeblocks(d_ctx, dtn_index, true);
	return 0;
}

static int dic_stage_tree_root(const struct silofs_dir_ctx *d_ctx,
                               struct silofs_dnode_info **out_dni)
{
	struct silofs_vaddr vaddr;

	dir_htree_root_addr(d_ctx->dir_ii, &vaddr);
	return dic_stage_dnode(d_ctx, &vaddr, out_dni);
}

static int dic_spawn_tree_root(const struct silofs_dir_ctx *d_ctx,
                               struct silofs_dnode_info **out_dni)
{
	struct silofs_vaddr vaddr = { .off = -1 };
	const silofs_dtn_index_t dtn_index = DTREE_INDEX_ROOT;
	int err;

	vaddr_of_dnode(&vaddr, SILOFS_OFF_NULL);
	err = dic_spawn_setup_dnode(d_ctx, &vaddr, dtn_index, out_dni);
	if (err) {
		return err;
	}
	dir_set_htree_root(d_ctx->dir_ii, dni_vaddr(*out_dni));
	ii_dirtify(d_ctx->dir_ii);
	return 0;
}

static int dic_require_tree_root(const struct silofs_dir_ctx *d_ctx,
                                 struct silofs_dnode_info **out_dni)
{
	int err;

	if (dir_has_htree(d_ctx->dir_ii)) {
		err = dic_stage_tree_root(d_ctx, out_dni);
	} else {
		err = dic_spawn_tree_root(d_ctx, out_dni);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dic_do_lookup_by_tree(const struct silofs_dir_ctx *d_ctx,
                                 struct silofs_dnode_info *root_dni,
                                 struct silofs_dir_entry_info *dei)
{
	const struct silofs_qstr *name = d_ctx->name;
	struct silofs_dnode_info *child_dni = NULL;
	struct silofs_dnode_info *dni = root_dni;
	silofs_dtn_depth_t depth;
	int ret = -ENOENT;

	for (depth = dtn_depth(dni->dtn); depth_isvalid(depth); ++depth) {
		ret = search_dnode(dni, name, dei);
		if (!ret || (ret != -ENOENT)) {
			break;
		}
		ret = dic_stage_child_by_name(d_ctx, dni, &child_dni);
		if (ret) {
			break;
		}
		dni = child_dni;
		ret = dni_check_child_depth(dni, depth);
		if (ret) {
			break;
		}
		ret = -ENOENT;
	}
	return ret;
}

static int dic_lookup_by_tree(const struct silofs_dir_ctx *d_ctx,
                              struct silofs_dnode_info *root_dni,
                              struct silofs_dir_entry_info *dei)
{
	int ret;

	dni_incref(root_dni);
	ret = dic_do_lookup_by_tree(d_ctx, root_dni, dei);
	dni_decref(root_dni);
	return ret;
}

static int dic_lookup_by_name(const struct silofs_dir_ctx *d_ctx,
                              struct silofs_dir_entry_info *dei)
{
	struct silofs_dnode_info *root_dni;
	int err;

	if (!dir_has_htree(d_ctx->dir_ii)) {
		return -ENOENT;
	}
	err = dic_stage_tree_root(d_ctx, &root_dni);
	if (err) {
		return err;
	}
	err = dic_lookup_by_tree(d_ctx, root_dni, dei);
	if (err) {
		return err;
	}
	return 0;
}

static int dic_check_self_and_name(const struct silofs_dir_ctx *d_ctx)
{
	if (!ii_isdir(d_ctx->dir_ii)) {
		return -ENOTDIR;
	}
	if (d_ctx->name->s.len == 0) {
		return -EINVAL;
	}
	if (d_ctx->name->s.len > SILOFS_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	return 0;
}

static void fill_ino_dt(struct silofs_ino_dt *ino_dt,
                        const struct silofs_dir_entry_info *dei)
{
	ino_dt->ino = dei->ino_dt.ino;
	ino_dt->dt = dei->ino_dt.dt;
}

static int dic_lookup_dentry(struct silofs_dir_ctx *d_ctx,
                             struct silofs_ino_dt *ino_dt)
{
	struct silofs_dir_entry_info dei;
	int ret;

	ii_incref(d_ctx->dir_ii);
	ret = dic_check_self_and_name(d_ctx);
	if (ret) {
		goto out;
	}
	ret = dic_lookup_by_name(d_ctx, &dei);
	if (ret) {
		goto out;
	}
	fill_ino_dt(ino_dt, &dei);
out:
	ii_decref(d_ctx->dir_ii);
	return ret;
}

int silofs_lookup_dentry(const struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_qstr *name,
                         struct silofs_ino_dt *out_idt)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.dir_ii = ii_unconst(dir_ii),
		.name = name,
		.stg_mode = SILOFS_STAGE_RO,
	};

	return dic_lookup_dentry(&d_ctx, out_idt);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dic_spawn_child(const struct silofs_dir_ctx *d_ctx,
                           const struct silofs_vaddr *parent,
                           silofs_dtn_index_t dtn_index,
                           struct silofs_dnode_info **out_dni)
{
	int err;

	if (!dtn_index_valid_depth(dtn_index)) {
		return -ENOSPC;
	}
	err = dic_spawn_setup_dnode(d_ctx, parent, dtn_index, out_dni);
	if (err) {
		return err;
	}
	dni_dirtify(*out_dni);
	return 0;
}

static int dic_do_spawn_bind_child(const struct silofs_dir_ctx *d_ctx,
                                   struct silofs_dnode_info *parent_dni,
                                   struct silofs_dnode_info **out_dni)
{
	const struct silofs_qstr *name = d_ctx->name;
	const struct silofs_vaddr *parent_vaddr = dni_vaddr(parent_dni);
	const uint64_t nhash = name->hash;
	silofs_dtn_index_t parent_dtn_index;
	silofs_dtn_index_t child_dtn_index;
	int err;

	parent_dtn_index = dtn_node_index(parent_dni->dtn);
	child_dtn_index = hash_to_child_dtn_index(nhash, parent_dtn_index);
	err = dic_spawn_child(d_ctx, parent_vaddr, child_dtn_index, out_dni);
	if (err) {
		return err;
	}
	dni_bind_child_at(parent_dni, dni_vaddr(*out_dni), child_dtn_index);
	return 0;
}

static int dic_spawn_bind_child(const struct silofs_dir_ctx *d_ctx,
                                struct silofs_dnode_info *parent_dni,
                                struct silofs_dnode_info **out_dni)
{
	int ret;

	dni_incref(parent_dni);
	ret = dic_do_spawn_bind_child(d_ctx, parent_dni, out_dni);
	dni_decref(parent_dni);
	return ret;
}

static int dic_require_child(const struct silofs_dir_ctx *d_ctx,
                             struct silofs_dnode_info *parent_dni,
                             struct silofs_dnode_info **out_dni)
{
	struct silofs_vaddr vaddr;
	const struct silofs_qstr *name = d_ctx->name;
	int err;

	dni_child_addr_by_hash(parent_dni, name->hash, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		err = dic_stage_child(d_ctx, parent_dni, &vaddr, out_dni);
	} else {
		err = dic_spawn_bind_child(d_ctx, parent_dni, out_dni);
	}
	return err;
}

static int dic_discard_dnode(const struct silofs_dir_ctx *d_ctx,
                             struct silofs_dnode_info *dni)
{
	const silofs_dtn_index_t dtn_index = dtn_node_index(dni->dtn);
	int err;

	dtn_reset_data(dni->dtn);
	err = dic_remove_dnode(d_ctx, dni);
	if (err) {
		return err;
	}
	dic_update_isizeblocks(d_ctx, dtn_index, false);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static nlink_t i_nlink_new(const struct silofs_inode_info *ii, long dif)
{
	return (nlink_t)((long)ii_nlink(ii) + dif);
}

static void dic_update_nlink(const struct silofs_dir_ctx *d_ctx, long dif)
{
	struct silofs_iattr iattr;
	struct silofs_inode_info *child_ii = d_ctx->child_ii;
	struct silofs_inode_info *dir_ii = d_ctx->dir_ii;
	const struct silofs_creds *creds = &d_ctx->task->t_oper.op_creds;

	silofs_iattr_setup(&iattr, ii_ino(child_ii));
	iattr.ia_nlink = i_nlink_new(child_ii, dif);
	iattr.ia_flags |= SILOFS_IATTR_NLINK;
	if (dif > 0) {
		iattr.ia_parent = ii_ino(dir_ii);
		iattr.ia_flags |= SILOFS_IATTR_PARENT;
	} else if (ii_parent(child_ii) == ii_ino(dir_ii)) {
		iattr.ia_parent = SILOFS_INO_NULL;
		iattr.ia_flags |= SILOFS_IATTR_PARENT;
	}
	ii_update_iattrs(child_ii, creds, &iattr);

	silofs_iattr_setup(&iattr, ii_ino(dir_ii));
	if (ii_isdir(child_ii)) {
		iattr.ia_nlink = i_nlink_new(dir_ii, dif);
		iattr.ia_flags |= SILOFS_IATTR_NLINK;
	}
	ii_update_iattrs(dir_ii, creds, &iattr);
}

static int dic_add_to_dnode(const struct silofs_dir_ctx *d_ctx,
                            struct silofs_dnode_info *dni)
{
	const struct silofs_inode_info *ii = d_ctx->child_ii;

	if (!dtn_may_insert(dni->dtn, d_ctx->name->s.len)) {
		return -ENOSPC;
	}
	dtn_insert(dni->dtn, d_ctx->name, ii_ino(ii), ii_dtype_of(ii));
	dir_inc_ndents(d_ctx->dir_ii);
	dni_dirtify(dni);
	return 0;
}

static int dic_add_to_tree(const struct silofs_dir_ctx *d_ctx,
                           struct silofs_dnode_info *root_dni)
{
	struct silofs_dnode_info *dni = root_dni;
	silofs_dtn_depth_t depth;
	int ret = -ENOSPC;

	dni_incref(root_dni);
	for (depth = dtn_depth(dni->dtn); depth_isvalid(depth); ++depth) {
		ret = dic_add_to_dnode(d_ctx, dni);
		if (ret == 0) {
			break;
		}
		ret = dic_require_child(d_ctx, dni, &dni);
		if (ret) {
			break;
		}
		ret = dni_check_child_depth(dni, depth);
		if (ret) {
			break;
		}
		ret = -ENOSPC;
	}
	dni_decref(root_dni);
	return ret;
}

static int dic_insert_dentry(struct silofs_dir_ctx *d_ctx,
                             struct silofs_dnode_info *root_dni)
{
	int err;

	err = dic_add_to_tree(d_ctx, root_dni);
	if (!err) {
		dic_update_nlink(d_ctx, 1);
	}
	return err;
}

static int dic_add_dentry(struct silofs_dir_ctx *d_ctx)
{
	struct silofs_dnode_info *root_dni = NULL;
	int ret;

	ii_incref(d_ctx->dir_ii);
	ii_incref(d_ctx->child_ii);
	ret = dic_require_tree_root(d_ctx, &root_dni);
	if (ret) {
		goto out;
	}
	ret = dic_insert_dentry(d_ctx, root_dni);
	if (ret) {
		goto out;
	}
out:
	ii_decref(d_ctx->child_ii);
	ii_decref(d_ctx->dir_ii);
	return ret;
}

int silofs_add_dentry(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_qstr *name,
                      struct silofs_inode_info *ii)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.dir_ii = dir_ii,
		.child_ii = ii,
		.name = name,
		.stg_mode = SILOFS_STAGE_RW,
	};

	return dic_add_dentry(&d_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dic_stage_inode(const struct silofs_dir_ctx *d_ctx, ino_t ino,
                           struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(d_ctx->task, ino, d_ctx->stg_mode, out_ii);
}

static int dic_check_stage_parent(struct silofs_dir_ctx *d_ctx)
{
	ino_t parent;
	int err;

	parent = ii_parent(d_ctx->dir_ii);
	if (ino_isnull(parent)) {
		/* special case: unlinked-but-open dir */
		return -ENOENT;
	}
	if (!ino_isvalid(parent)) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = dic_stage_inode(d_ctx, parent, &d_ctx->parent_ii);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool
dic_isindex_inrange(const struct silofs_dir_ctx *d_ctx, size_t index)
{
	const size_t dtn_index = dic_last_node_index_of(d_ctx);
	const size_t dtn_index_null = DTREE_INDEX_NULL;

	return (dtn_index != dtn_index_null) ? (index <= dtn_index) : false;
}

static bool dic_inrange(const struct silofs_dir_ctx *d_ctx)
{
	const loff_t doff = d_ctx->rd_ctx->pos;
	bool ret = false;

	if (doff >= 0) {
		ret = dic_isindex_inrange(d_ctx, doff_to_dtn_index(doff));
	}
	return ret;
}

static bool dic_stopped(const struct silofs_dir_ctx *d_ctx)
{
	return !d_ctx->keep_iter;
}

static bool dic_emit(struct silofs_dir_ctx *d_ctx, const char *name,
                     size_t nlen, ino_t ino, mode_t dt,
                     const struct stat *attr)
{
	struct silofs_readdir_ctx *rd_ctx = d_ctx->rd_ctx;
	struct silofs_readdir_info rdi = {
		.attr.st_ino = ino,
		.name = name,
		.namelen = nlen,
		.ino = ino,
		.dt = dt,
		.off = rd_ctx->pos
	};
	int err;

	if ((attr != NULL) && d_ctx->readdir_plus) {
		memcpy(&rdi.attr, attr, sizeof(rdi.attr));
	}
	err = rd_ctx->actor(rd_ctx, &rdi);
	d_ctx->keep_iter = (err == 0);
	return d_ctx->keep_iter;
}

static bool dic_emit_dirent(struct silofs_dir_ctx *d_ctx,
                            const struct silofs_dtree_node *dtn,
                            const struct silofs_dir_entry *de, loff_t doff,
                            const struct silofs_inode_info *ii)
{
	const ino_t ino = de_ino(de);
	const mode_t dt = de_dt(de);
	const size_t nlen = de_name_len(de);
	const char *name = dtn_name_of(dtn, de);
	const struct stat *attr = NULL;
	struct stat st;

	if (ii != NULL) {
		silofs_stat_of(ii, &st);
		attr = &st;
	}

	d_ctx->rd_ctx->pos = doff;
	return dic_emit(d_ctx, name, nlen, ino, dt, attr);
}

static bool dic_emit_ii(struct silofs_dir_ctx *d_ctx, const char *name,
                        size_t nlen, const struct silofs_inode_info *ii)
{
	const ino_t xino = ii_xino(ii);
	const mode_t mode = ii_mode(ii);
	struct stat attr;

	silofs_stat_of(ii, &attr);
	return dic_emit(d_ctx, name, nlen, xino, IFTODT(mode), &attr);
}

static int dic_stage_inode_of_de(const struct silofs_dir_ctx *d_ctx,
                                 const struct silofs_dir_entry *de,
                                 struct silofs_inode_info **out_ii)
{
	int err = 0;

	*out_ii = NULL;
	if (d_ctx->readdir_plus) {
		err = dic_stage_inode(d_ctx, de_ino(de), out_ii);
	}
	return err;
}

static int dic_iterate_node(struct silofs_dir_ctx *d_ctx,
                            const struct silofs_dnode_info *dni)
{
	const struct silofs_dir_entry *de = NULL;
	struct silofs_inode_info *ii = NULL;
	loff_t off;
	int err;
	bool ok;

	while (!dic_stopped(d_ctx)) {
		de = dtn_scan(dni->dtn, d_ctx->rd_ctx->pos);
		if (!de) {
			off = dtn_next_doffset(dni->dtn);
			d_ctx->rd_ctx->pos = off;
			break;
		}
		off = dtn_doffset_of(dni->dtn, de);
		err = dic_stage_inode_of_de(d_ctx, de, &ii);
		if (err) {
			return err;
		}
		ok = dic_emit_dirent(d_ctx, dni->dtn, de, off, ii);
		if (!ok) {
			break;
		}
		d_ctx->rd_ctx->pos += 1;
	}
	return 0;
}

static int dic_readdir_eos(struct silofs_dir_ctx *d_ctx)
{
	d_ctx->rd_ctx->pos = -1;
	dic_emit(d_ctx, "", 0, SILOFS_INO_NULL, 0, NULL);

	d_ctx->keep_iter = false;
	return 0;
}

static int dic_stage_child_by_ord(struct silofs_dir_ctx *d_ctx,
                                  struct silofs_dnode_info *dni,
                                  silofs_dtn_ord_t ord,
                                  struct silofs_dnode_info **out_dni)
{
	struct silofs_vaddr vaddr;
	int ret;

	dni_incref(dni);
	if (ord >= DTREE_FANOUT) {
		ret = -ENOENT;
		goto out;
	}
	dni_child_addr_by_ord(dni, ord, &vaddr);
	ret = dic_stage_dnode(d_ctx, &vaddr, out_dni);
	if (ret) {
		goto out;
	}
out:
	dni_decref(dni);
	return ret;
}

static int
dic_stage_node_by_index(struct silofs_dir_ctx *d_ctx,
                        const struct silofs_dnode_info *root_dni,
                        silofs_dtn_index_t dtn_index,
                        struct silofs_dnode_info **out_dni)
{
	silofs_dtn_ord_t child_ord[DTREE_DEPTH_MAX];
	silofs_dtn_depth_t depth;
	silofs_dtn_ord_t ord;
	int err;

	depth = dtn_index_depth(dtn_index);
	if (depth >= ARRAY_SIZE(child_ord)) {
		return -ENOENT;
	}
	for (silofs_dtn_depth_t d = depth; d > 0; --d) {
		child_ord[d - 1] = dtn_index_to_child_ord(dtn_index);
		dtn_index = dtn_index_to_parent(dtn_index);
	}
	*out_dni = dni_unconst(root_dni);
	for (size_t i = 0; i < depth; ++i) {
		ord = child_ord[i];
		err = dic_stage_child_by_ord(d_ctx, *out_dni, ord, out_dni);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int dic_next_node(struct silofs_dir_ctx *d_ctx,
                         const struct silofs_dnode_info *dni,
                         silofs_dtn_index_t *out_dtn_index)
{
	struct silofs_vaddr vaddr = { .off = -1 };
	struct silofs_dnode_info *parent_dni = NULL;
	silofs_dtn_index_t next_dtn_index;
	silofs_dtn_index_t curr_dtn_index;
	silofs_dtn_ord_t ord;
	int err;

	curr_dtn_index = dtn_node_index(dni->dtn);
	next_dtn_index = curr_dtn_index + 1;

	dtn_parent_addr(dni->dtn, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		*out_dtn_index = next_dtn_index;
		return 0;
	}
	err = dic_stage_dnode(d_ctx, &vaddr, &parent_dni);
	if (err) {
		return err;
	}
	ord = dtn_child_ord(dni->dtn);
	while (++ord < DTREE_FANOUT) {
		dni_child_addr_by_ord(parent_dni, ord, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			break;
		}
		next_dtn_index += 1;
	}
	*out_dtn_index = next_dtn_index;
	return 0;
}

static int dic_do_iterate_tree_nodes(struct silofs_dir_ctx *d_ctx,
                                     const struct silofs_dnode_info *root_dni)
{
	struct silofs_dnode_info *dni = NULL;
	silofs_dtn_index_t dtn_index;
	int ret = 0;

	dtn_index = dic_curr_node_index_of(d_ctx);
	while (!ret && !dic_stopped(d_ctx)) {
		if (!dic_isindex_inrange(d_ctx, dtn_index)) {
			ret = dic_readdir_eos(d_ctx);
			break;
		}
		ret = dic_stage_node_by_index(d_ctx, root_dni,
		                              dtn_index, &dni);
		if (ret == -ENOENT) {
			dtn_index++;
			ret = 0;
			continue;
		}
		if (ret) {
			break;
		}
		ret = dic_iterate_node(d_ctx, dni);
		if (ret) {
			break;
		}
		ret = dic_next_node(d_ctx, dni, &dtn_index);
	}
	return ret;
}


static int dic_iterate_tree_nodes(struct silofs_dir_ctx *d_ctx,
                                  struct silofs_dnode_info *root_dni)
{
	int ret;

	dni_incref(root_dni);
	ret = dic_do_iterate_tree_nodes(d_ctx, root_dni);
	dni_decref(root_dni);
	return ret;
}

static int dic_iterate_tree(struct silofs_dir_ctx *d_ctx)
{
	struct silofs_dnode_info *root_dni = NULL;
	const size_t start_index = dic_curr_node_index_of(d_ctx);
	int err;

	if (!dic_isindex_inrange(d_ctx, start_index)) {
		return dic_readdir_eos(d_ctx);
	}
	err = dic_stage_tree_root(d_ctx, &root_dni);
	if (err) {
		return err;
	}
	err = dic_iterate_tree_nodes(d_ctx, root_dni);
	if (err) {
		return err;
	}
	return 0;
}

static int dic_iterate(struct silofs_dir_ctx *d_ctx)
{
	int err;

	if (!dir_has_htree(d_ctx->dir_ii)) {
		return dic_readdir_eos(d_ctx);
	}
	err = dic_iterate_tree(d_ctx);
	if (err || dic_stopped(d_ctx)) {
		return err;
	}
	return dic_readdir_eos(d_ctx);
}

static int dic_readdir_emit(struct silofs_dir_ctx *d_ctx)
{
	struct silofs_iattr iattr;
	const struct silofs_creds *creds = &d_ctx->task->t_oper.op_creds;
	int err = 0;
	bool ok = true;

	if (d_ctx->rd_ctx->pos == 0) {
		ok = dic_emit_ii(d_ctx, ".", 1, d_ctx->dir_ii);
		d_ctx->rd_ctx->pos = 1;
	}
	if (ok && (d_ctx->rd_ctx->pos == 1)) {
		ok = dic_emit_ii(d_ctx, "..", 2, d_ctx->parent_ii);
		d_ctx->rd_ctx->pos = 2;
	}
	if (ok && !dic_inrange(d_ctx)) {
		err = dic_readdir_eos(d_ctx);
	}
	if (ok && !dic_stopped(d_ctx)) {
		err = dic_iterate(d_ctx);
	}

	silofs_iattr_setup(&iattr, ii_ino(d_ctx->dir_ii));
	iattr.ia_flags |= SILOFS_IATTR_ATIME | SILOFS_IATTR_LAZY;
	ii_update_iattrs(d_ctx->dir_ii, creds, &iattr);

	return err;
}

/*
 * TODO-0030: Does READDIR should do RD-access check?
 *
 * What is the expected behavior when doing readdir via open file-descriptor,
 * and then change inodes access permissions?
 */
static int dic_check_raccess(const struct silofs_dir_ctx *d_ctx)
{
	return silofs_do_access(d_ctx->task, d_ctx->dir_ii, R_OK);
}

static int dic_check_dir_io(const struct silofs_dir_ctx *d_ctx)
{
	const struct silofs_inode_info *ii = d_ctx->dir_ii;

	if (!ii_isdir(ii)) {
		return -ENOTDIR;
	}
	if (!ii->i_nopen) {
		return -EBADF;
	}
	return 0;
}

static int dic_readdir(struct silofs_dir_ctx *d_ctx)
{
	int ret;

	ii_incref(d_ctx->dir_ii);
	ret = dic_check_dir_io(d_ctx);
	if (ret) {
		goto out;
	}
	ret = dic_check_raccess(d_ctx);
	if (ret) {
		goto out;
	}
	ret = dic_check_stage_parent(d_ctx);
	if (ret) {
		goto out;
	}
	ret = dic_readdir_emit(d_ctx);
	if (ret) {
		goto out;
	}
out:
	ii_decref(d_ctx->dir_ii);
	return ret;
}

int silofs_do_readdir(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.rd_ctx = rd_ctx,
		.dir_ii = dir_ii,
		.keep_iter = true,
		.readdir_plus = 0,
		.stg_mode = SILOFS_STAGE_RO,
	};

	return dic_readdir(&d_ctx);
}

int silofs_do_readdirplus(const struct silofs_task *task,
                          struct silofs_inode_info *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.rd_ctx = rd_ctx,
		.dir_ii = dir_ii,
		.keep_iter = true,
		.readdir_plus = 1,
		.stg_mode = SILOFS_STAGE_RO,
	};

	return dic_readdir(&d_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dic_discard_recursively(struct silofs_dir_ctx *d_ctx,
                                   const struct silofs_vaddr *vaddr);

static int dic_discard_childs_of(struct silofs_dir_ctx *d_ctx,
                                 struct silofs_dnode_info *dni)
{
	struct silofs_vaddr child_vaddr;
	silofs_dtn_ord_t ord;
	int ret = 0;

	dni_incref(dni);
	for (ord = 0; (ord < DTREE_FANOUT) && !ret; ++ord) {
		dtn_child_by_ord(dni->dtn, ord, &child_vaddr);
		ret = dic_discard_recursively(d_ctx, &child_vaddr);
	}
	dni_decref(dni);
	return ret;
}

static int dic_discard_tree_at(struct silofs_dir_ctx *d_ctx,
                               struct silofs_dnode_info *dni)
{
	int err;

	err = dic_discard_childs_of(d_ctx, dni);
	if (err) {
		return err;
	}
	err = dic_discard_dnode(d_ctx, dni);
	if (err) {
		return err;
	}
	return 0;
}

static int dic_discard_recursively(struct silofs_dir_ctx *d_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	struct silofs_dnode_info *dni = NULL;
	int err;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = dic_stage_dnode(d_ctx, vaddr, &dni);
	if (err) {
		return err;
	}
	err = dic_discard_tree_at(d_ctx, dni);
	if (err) {
		return err;
	}
	return 0;
}

static int dic_finalize_tree(struct silofs_dir_ctx *d_ctx)
{
	struct silofs_dnode_info *root_dni = NULL;
	struct silofs_inode_info *dir_ii = d_ctx->dir_ii;
	int err;

	if (!dir_has_htree(dir_ii)) {
		return 0;
	}
	err = dic_stage_tree_root(d_ctx, &root_dni);
	if (err) {
		return err;
	}
	err = dic_discard_tree_at(d_ctx, root_dni);
	if (err) {
		return err;
	}
	silofs_setup_dir(dir_ii, 0, ii_nlink(dir_ii));
	ii_dirtify(dir_ii);
	return 0;
}

int silofs_drop_dir(const struct silofs_task *task,
                    struct silofs_inode_info *dir_ii)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.dir_ii = dir_ii,
	};
	int err;

	ii_incref(dir_ii);
	err = dic_finalize_tree(&d_ctx);
	ii_decref(dir_ii);
	return err;
}

/*
 * TODO-0005: Squeeze tree
 *
 * Currently, we drop tree only when its empty. Try to squeeze it up and
 * remove empty leaf nodes.
 */
static int dic_erase_dentry(struct silofs_dir_ctx *d_ctx,
                            const struct silofs_dir_entry_info *dei)
{
	struct silofs_inode_info *dir_ii = d_ctx->dir_ii;
	int ret;

	ii_incref(d_ctx->child_ii);

	dtn_remove(dei->dni->dtn, dei->de);
	dni_dirtify(dei->dni);

	dir_dec_ndents(dir_ii);
	dic_update_nlink(d_ctx, -1);

	ret = !dir_ndents(dir_ii) ? dic_finalize_tree(d_ctx) : 0;

	ii_decref(d_ctx->child_ii);

	return ret;
}

static int dic_check_and_lookup_by_name(struct silofs_dir_ctx *d_ctx,
                                        struct silofs_dir_entry_info *dei)
{
	int err;

	err = dic_check_self_and_name(d_ctx);
	if (err) {
		return err;
	}
	err = dic_lookup_by_name(d_ctx, dei);
	if (err) {
		return err;
	}
	return 0;
}

static int dic_stage_child_by_de(struct silofs_dir_ctx *d_ctx,
                                 const struct silofs_dir_entry_info *dei)
{
	const ino_t ino = dei->ino_dt.ino;
	int err;

	dni_incref(dei->dni);
	err = dic_stage_inode(d_ctx, ino, &d_ctx->child_ii);
	dni_decref(dei->dni);
	return err;
}

static int dic_remove_dentry(struct silofs_dir_ctx *d_ctx)
{
	struct silofs_dir_entry_info dei;
	int ret;

	ii_incref(d_ctx->dir_ii);
	ret = dic_check_and_lookup_by_name(d_ctx, &dei);
	if (ret) {
		goto out;
	}
	ret = dic_stage_child_by_de(d_ctx, &dei);
	if (ret) {
		goto out;
	}
	ret = dic_erase_dentry(d_ctx, &dei);
	if (ret) {
		goto out;
	}
out:
	ii_decref(d_ctx->dir_ii);
	return ret;
}

int silofs_remove_dentry(const struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_qstr *name)
{
	struct silofs_dir_ctx d_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.dir_ii = ii_unconst(dir_ii),
		.name = name,
		.stg_mode = SILOFS_STAGE_RW,
	};

	return dic_remove_dentry(&d_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_dtn_index(silofs_dtn_index_t dtn_index, bool has_tree)
{
	int err;

	if (has_tree) {
		err = dtn_index_isvalid(dtn_index) ? 0 : -SILOFS_EFSCORRUPTED;
	} else {
		err = dtn_index_isnull(dtn_index) ? 0 : -SILOFS_EFSCORRUPTED;
	}
	return err;
}

static int verify_dir_root(const struct silofs_inode *inode)
{
	const struct silofs_inode_dir *idr = idr_of(inode);
	loff_t root_off;
	int err;

	root_off = idr_htree_root(idr);
	err = silofs_verify_off(root_off);
	if (err) {
		return err;
	}
	err = verify_dtn_index(idr_last_index(idr), !off_isnull(root_off));
	if (err) {
		return err;
	}
	return 0;
}

int silofs_verify_dir_inode(const struct silofs_inode *inode)
{
	int err;

	/* TODO: Check more */
	err = verify_dir_root(inode);
	if (err) {
		return err;
	}
	return 0;
}

static int verify_childs_of(const struct silofs_dtree_node *dtn)
{
	struct silofs_vaddr vaddr;
	int err;

	for (unsigned int i = 0; i < ARRAY_SIZE(dtn->dn_child); ++i) {
		dtn_child(dtn, i, &vaddr);
		if (vaddr_isnull(&vaddr)) {
			continue;
		}
		err = silofs_verify_off(vaddr.off);
		if (err) {
			return err;
		}
		if (!stype_isequal(vaddr.stype, SILOFS_STYPE_DTNODE)) {
			return -SILOFS_EFSCORRUPTED;
		}
	}
	return 0;
}

int silofs_verify_dtree_node(const struct silofs_dtree_node *dtn)
{
	int err;

	err = silofs_verify_ino(dtn_ino(dtn));
	if (err) {
		return err;
	}
	err = silofs_verify_off(dtn_parent(dtn));
	if (err) {
		return err;
	}
	err = verify_dtn_index(dtn_node_index(dtn), true);
	if (err) {
		return err;
	}
	err = verify_childs_of(dtn);
	if (err) {
		return err;
	}
	err = dtn_verify_des(dtn);
	if (err) {
		return err;
	}
	err = dtn_verify_names(dtn);
	if (err) {
		return err;
	}
	return 0;
}
