/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

/* single entry of free vspace */
struct silofs_spa_entry {
	struct silofs_avl_node spe_an;
	loff_t spe_voff;
	size_t spe_len;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spalifo_clear(struct silofs_spalifo *spal)
{
	silofs_memzero(spal->sal_lifo, sizeof(spal->sal_lifo));
	spal->sal_size = 0;
}

static void spalifo_init(struct silofs_spalifo *spal, unsigned int ulen)
{
	spalifo_clear(spal);
	spal->sal_ulen = ulen;
}

static void spalifo_fini(struct silofs_spalifo *spal)
{
	spalifo_clear(spal);
}

static int
spalifo_pop_vspace(struct silofs_spalifo *spal, size_t len, loff_t *out_off)
{
	if (!spal->sal_size || (spal->sal_ulen != len)) {
		return -SILOFS_ENOENT;
	}
	*out_off = spal->sal_lifo[spal->sal_size - 1];
	spal->sal_size--;
	return 0;
}

static int
spalifo_add_vspace(struct silofs_spalifo *spal, loff_t off, size_t len)
{
	const size_t size_max = ARRAY_SIZE(spal->sal_lifo);

	if (!(spal->sal_size < size_max) || (spal->sal_ulen != len)) {
		return -SILOFS_ENOSPC;
	}
	spal->sal_lifo[spal->sal_size] = off;
	spal->sal_size++;
	return 0;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long voff_compare(const void *x, const void *y)
{
	const loff_t *voff_x = x;
	const loff_t *voff_y = y;

	return *voff_y - *voff_x;
}

static struct silofs_spa_entry *
avl_node_to_spe(const struct silofs_avl_node *an)
{
	const struct silofs_spa_entry *spe = NULL;

	if (an != NULL) {
		spe = container_of2(an, struct silofs_spa_entry, spe_an);
	}
	return unconst(spe);
}

static const void *spe_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_spa_entry *spe = avl_node_to_spe(an);

	return &spe->spe_voff;
}

static void spe_init(struct silofs_spa_entry *spe, loff_t voff, size_t len)
{
	silofs_avl_node_init(&spe->spe_an);
	spe->spe_voff = voff;
	spe->spe_len = len;
}

static void spe_fini(struct silofs_spa_entry *spe)
{
	silofs_avl_node_fini(&spe->spe_an);
	spe->spe_voff = SILOFS_OFF_NULL;
	spe->spe_len = 0;
}

static loff_t spe_end(const struct silofs_spa_entry *spe)
{
	return off_end(spe->spe_voff, spe->spe_len);
}

static bool spe_is_within(const struct silofs_spa_entry *spe, loff_t voff)
{
	return (voff >= spe->spe_voff) && (voff < spe_end(spe));
}

static void spe_chop_head(struct silofs_spa_entry *spe, size_t len)
{
	silofs_assert_lt(len, spe->spe_len);

	spe->spe_voff = off_end(spe->spe_voff, len);
	spe->spe_len -= len;
}

static struct silofs_spa_entry *
spe_new(loff_t voff, size_t len, struct silofs_alloc *alloc)
{
	struct silofs_spa_entry *spe;

	spe = silofs_memalloc(alloc, sizeof(*spe), 0);
	if (spe != NULL) {
		spe_init(spe, voff, len);
	}
	return spe;
}

static void spe_del(struct silofs_spa_entry *spe, struct silofs_alloc *alloc)
{
	if (spe != NULL) { /* make gcc-analyzer happy */
		spe_fini(spe);
		silofs_memfree(alloc, spe, sizeof(*spe), 0);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static unsigned int spamap_capacity(enum silofs_ltype ltype)
{
	const uint32_t mega = SILOFS_MEGA;
	const uint32_t nmul = ltype_isdata(ltype) ? 16 : 4;

	return (nmul * mega);
}

static struct silofs_spa_entry *
spamap_new_spe(struct silofs_spamap *spa, loff_t voff, size_t len)
{
	struct silofs_spa_entry *spe;

	spe = spe_new(voff, len, spa->spa_alloc);
	return spe;
}

static void
spamap_delete_spe(struct silofs_spamap *spa, struct silofs_spa_entry *spe)
{
	spe_del(spe, spa->spa_alloc);
}

static struct silofs_spa_entry *
spamap_minimal_spe(const struct silofs_spamap *spa)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	if (avl->size == 0) {
		return NULL;
	}
	an = silofs_avl_begin(avl);
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spamap_maximal_spe(const struct silofs_spamap *spa)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	if (avl->size == 0) {
		return NULL;
	}
	an = silofs_avl_rbegin(avl);
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_lower_bound_spe(const struct silofs_spamap *spa, loff_t off)
{
	const struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_prev_of(const struct silofs_spamap *spa,
              const struct silofs_spa_entry *spe)
{
	struct silofs_spa_entry *spe_prev = NULL;
	const struct silofs_avl_node *an_prev = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	an_prev = silofs_avl_prev(avl, &spe->spe_an);
	if (an_prev != silofs_avl_end(avl)) {
		spe_prev = avl_node_to_spe(an_prev);
	}
	return spe_prev;
}

static void spmap_find_next_prev(const struct silofs_spamap *spa, loff_t off,
                                 struct silofs_spa_entry **out_spe_prev,
                                 struct silofs_spa_entry **out_spe_next)
{
	struct silofs_spa_entry *spe_next = NULL;
	struct silofs_spa_entry *spe_prev = NULL;

	spe_next = spmap_lower_bound_spe(spa, off);
	if (spe_next != NULL) {
		spe_prev = spmap_prev_of(spa, spe_next);
	} else {
		spe_prev = spamap_maximal_spe(spa);
	}
	*out_spe_prev = spe_prev;
	*out_spe_next = spe_next;
}

static void
spamap_insert_spe(struct silofs_spamap *spa, struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_insert(avl, an);
}

static void
spamap_remove_spe(struct silofs_spamap *spa, struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_remove(avl, an);
}

static void
spamap_evict_spe(struct silofs_spamap *spa, struct silofs_spa_entry *spe)
{
	spamap_remove_spe(spa, spe);
	spamap_delete_spe(spa, spe);
}

static int spamap_check_cap_add(const struct silofs_spamap *spa)
{
	const size_t spe_size = sizeof(struct silofs_spa_entry);
	const size_t cap_cur = spa->spa_avl.size * spe_size;
	const size_t cap_max = spa->spa_cap_max;

	return (cap_cur < cap_max) ? 0 : -SILOFS_ENOMEM;
}

static int
spamap_pop_vspace(struct silofs_spamap *spa, size_t len, loff_t *out_off)
{
	struct silofs_spa_entry *spe;
	int err;

	err = spalifo_pop_vspace(&spa->spa_lifo, len, out_off);
	if (!err) {
		return 0;
	}
	spe = spamap_minimal_spe(spa);
	if (spe == NULL) {
		return -SILOFS_ENOSPC;
	}
	if (len > spe->spe_len) {
		return -SILOFS_ENOSPC;
	}
	*out_off = spe->spe_voff;
	if (len < spe->spe_len) {
		/* its ok to modify in-place and avoid the costly remove-insert
		 * into the tree, as this is already the minimal element */
		spe_chop_head(spe, len);
	} else {
		spamap_evict_spe(spa, spe);
	}
	return 0;
}

static int
spamap_merge_vspace(struct silofs_spamap *spa, loff_t off, size_t len)
{
	struct silofs_spa_entry *spe = NULL;
	struct silofs_spa_entry *spe_prev = NULL;
	struct silofs_spa_entry *spe_next = NULL;
	loff_t end;
	int ret = -SILOFS_ENOENT;

	end = off_end(off, len);
	spmap_find_next_prev(spa, off, &spe_prev, &spe_next);

	if (spe_prev && (spe_end(spe_prev) == off)) {
		/* merge range into prev */
		spe = spe_prev;
		spe->spe_len += len;
		off = spe->spe_voff;
		end = spe_end(spe);
		ret = 0;
	}
	if (spe_next == NULL) {
		/* no next to append with */
		return ret;
	}
	if (end != spe_next->spe_voff) {
		/* can not merge with next */
		return ret;
	}
	end = spe_end(spe_next);
	if (spe == NULL) {
		/* merge with next only */
		spamap_evict_spe(spa, spe_next);
		spe = spamap_new_spe(spa, off, off_ulen(off, end));
		if (spe == NULL) {
			return -SILOFS_ENOMEM;
		}
		spamap_insert_spe(spa, spe);
	} else {
		/* full merge (prev + next ) */
		spe->spe_len += spe_next->spe_len;
		spamap_evict_spe(spa, spe_next);
	}
	return 0;
}

static int
spamap_insert_vspace(struct silofs_spamap *spa, loff_t off, size_t len)
{
	struct silofs_spa_entry *spe;
	struct silofs_spa_entry *spe_max = NULL;

	spe = spamap_new_spe(spa, off, len);
	if (spe != NULL) {
		goto out_ok; /* trivial case */
	}
	spe_max = spamap_maximal_spe(spa);
	if (spe_max == NULL) {
		return -SILOFS_ENOMEM;
	}
	if (off > spe_max->spe_voff) {
		return -SILOFS_ENOMEM;
	}
	spamap_delete_spe(spa, spe_max);
	spe = spamap_new_spe(spa, off, len);
	if (spe == NULL) {
		return -SILOFS_ENOMEM;
	}
out_ok:
	spamap_insert_spe(spa, spe);
	return 0;
}

static int spamap_add_vspace(struct silofs_spamap *spa, loff_t off, size_t len)
{
	int err;

	err = spalifo_add_vspace(&spa->spa_lifo, off, len);
	if (!err) {
		return 0;
	}
	err = spamap_merge_vspace(spa, off, len);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = spamap_check_cap_add(spa);
	if (err) {
		return err;
	}
	err = spamap_insert_vspace(spa, off, len);
	if (err) {
		return err;
	}
	return 0;
}

static int spamap_find_baseof(const struct silofs_spamap *spa, loff_t off,
                              loff_t *out_base_off)
{
	struct silofs_spa_entry *spe;

	spe = spmap_lower_bound_spe(spa, off);
	if (spe == NULL) {
		return -SILOFS_ENOENT;
	}
	spe = spmap_prev_of(spa, spe);
	if (spe == NULL) {
		return -SILOFS_ENOENT;
	}
	if (!spe_is_within(spe, off)) {
		return -SILOFS_ENOENT;
	}
	*out_base_off = spe->spe_voff;
	return 0;
}

static void spamap_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_spamap *spa = p;
	struct silofs_spa_entry *spe = avl_node_to_spe(an);

	spamap_delete_spe(spa, spe);
}

static void spamap_clear(struct silofs_spamap *spa)
{
	const struct silofs_avl_node_functor fn = {
		.fn = spamap_avl_node_delete_cb,
		.ctx = spa
	};

	silofs_avl_clear(&spa->spa_avl, &fn);
	spalifo_clear(&spa->spa_lifo);
}

static loff_t spamap_get_hint(const struct silofs_spamap *spa)
{
	return spa->spa_hint;
}

static void spamap_set_hint(struct silofs_spamap *spa, loff_t off)
{
	spa->spa_hint = off;
}

static void spamap_init(struct silofs_spamap *spa, enum silofs_ltype ltype,
                        struct silofs_alloc *alloc)
{
	spalifo_init(&spa->spa_lifo, (unsigned int)ltype_size(ltype));
	silofs_avl_init(&spa->spa_avl, spe_getkey, voff_compare, spa);
	spa->spa_alloc = alloc;
	spa->spa_cap_max = spamap_capacity(ltype);
	spa->spa_ltype = ltype;
	spa->spa_hint = 0;
}

static void spamap_fini(struct silofs_spamap *spa)
{
	spalifo_fini(&spa->spa_lifo);
	silofs_avl_fini(&spa->spa_avl);
	spa->spa_alloc = NULL;
	spa->spa_cap_max = 0;
	spa->spa_ltype = SILOFS_LTYPE_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spamap *
spamaps_sub_map(struct silofs_spamaps *spam, enum silofs_ltype ltype)
{
	struct silofs_spamap *ret;

	switch (ltype) {
	case SILOFS_LTYPE_DATA1K:
		ret = &spam->spa_data1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &spam->spa_data4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &spam->spa_databk;
		break;
	case SILOFS_LTYPE_INODE:
		ret = &spam->spa_inode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &spam->spa_xanode;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &spam->spa_dtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &spam->spa_ftnode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &spam->spa_symval;
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static const struct silofs_spamap *
spamaps_sub_map2(const struct silofs_spamaps *spam, enum silofs_ltype ltype)
{
	return spamaps_sub_map(unconst(spam), ltype);
}

int silofs_spamaps_store(struct silofs_spamaps *spam, enum silofs_ltype ltype,
                         loff_t voff, size_t len)
{
	struct silofs_spamap *spa;
	int err = -SILOFS_EINVAL;

	spa = spamaps_sub_map(spam, ltype);
	if (spa != NULL) {
		err = spamap_add_vspace(spa, voff, len);
	}
	return err;
}

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_ltype ltype,
                          size_t len, loff_t *out_voff)
{
	struct silofs_spamap *spa;
	int err = -SILOFS_EINVAL;

	spa = spamaps_sub_map(spam, ltype);
	if (spa != NULL) {
		err = spamap_pop_vspace(spa, len, out_voff);
	}
	return err;
}

/* TODO: unused; remove me */
int silofs_spamaps_baseof(const struct silofs_spamaps *spam,
                          enum silofs_ltype ltype, loff_t voff, loff_t *out)
{
	const struct silofs_spamap *spa;
	int err = -SILOFS_ENOENT;

	spa = spamaps_sub_map2(spam, ltype);
	if (spa != NULL) {
		err = spamap_find_baseof(spa, voff, out);
	}
	return err;
}

loff_t silofs_spamaps_get_hint(const struct silofs_spamaps *spam,
                               enum silofs_ltype ltype)
{
	const struct silofs_spamap *spa;
	loff_t hint = 0;

	spa = spamaps_sub_map2(spam, ltype);
	if (spa != NULL) {
		hint = spamap_get_hint(spa);
	}
	return hint;
}

void silofs_spamaps_set_hint(struct silofs_spamaps *spam,
                             enum silofs_ltype ltype, loff_t off)
{
	struct silofs_spamap *spa;

	spa = spamaps_sub_map(spam, ltype);
	if (spa != NULL) {
		spamap_set_hint(spa, off);
	}
}

void silofs_spamaps_drop(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		spa = spamaps_sub_map(spam, ltype);
		if (spa != NULL) {
			spamap_clear(spa);
		}
	}
}

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc *alloc)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		spa = spamaps_sub_map(spam, ltype);
		if (spa != NULL) {
			spamap_init(spa, ltype, alloc);
		}
	}
	return 0;
}

void silofs_spamaps_fini(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		spa = spamaps_sub_map(spam, ltype);
		if (spa != NULL) {
			spamap_clear(spa);
			spamap_fini(spa);
		}
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static enum silofs_ltype uaddr_vspace(const struct silofs_uaddr *uaddr)
{
	return uaddr->laddr.lsid.vspace;
}

static void uakey_setup(struct silofs_uakey *uakey, loff_t voff,
                        enum silofs_height height, enum silofs_ltype vspace)
{
	uakey->voff = voff;
	uakey->height = height;
	uakey->vspace = vspace;
}

void silofs_uakey_setup_by(struct silofs_uakey *uakey,
                           const struct silofs_uaddr *uaddr)
{
	uakey_setup(uakey, uaddr->voff, uaddr_height(uaddr),
	            uaddr_vspace(uaddr));
}

void silofs_uakey_setup_by2(struct silofs_uakey *uakey,
                            const struct silofs_vrange *vrange,
                            enum silofs_ltype vspace)
{
	uakey_setup(uakey, vrange->beg, vrange->height, vspace);
}

static bool uakey_isequal(const struct silofs_uakey *uakey1,
                          const struct silofs_uakey *uakey2)
{
	return ((uakey1->voff == uakey2->voff) &&
	        (uakey1->height == uakey2->height) &&
	        (uakey1->vspace == uakey2->vspace));
}

static uint64_t uakey_hash(const struct silofs_uakey *uakey)
{
	const uint64_t off = (uint64_t)(uakey->voff);
	const uint64_t nlz = silofs_clz_u64(off);
	uint64_t hval;

	hval = off;
	hval ^= (0x5D21C111ULL / (nlz + 1));
	hval ^= ~((uint64_t)(uakey->vspace) << 43);
	hval ^= (uint64_t)(0xCAFEFEEDULL << (31 - uakey->height));
	return hval;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uaent {
	struct silofs_list_head htb_lh;
	struct silofs_list_head lru_lh;
	struct silofs_uaddr uaddr;
};

static void
uaent_init(struct silofs_uaent *uae, const struct silofs_uaddr *uaddr)
{
	list_head_init(&uae->htb_lh);
	list_head_init(&uae->lru_lh);
	uaddr_assign(&uae->uaddr, uaddr);
}

static void uaent_fini(struct silofs_uaent *uae)
{
	list_head_fini(&uae->htb_lh);
	list_head_fini(&uae->lru_lh);
	uaddr_reset(&uae->uaddr);
}

static struct silofs_uaent *
uaent_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_uaent *uae = NULL;

	uae = silofs_memalloc(alloc, sizeof(*uae), 0);
	if (uae != NULL) {
		uaent_init(uae, uaddr);
	}
	return uae;
}

static void uaent_del(struct silofs_uaent *uae, struct silofs_alloc *alloc)
{
	uaent_fini(uae);
	silofs_memfree(alloc, uae, sizeof(*uae), 0);
}

static bool uaent_has_mapping(const struct silofs_uaent *uaent,
                              const struct silofs_uakey *uakey)
{
	struct silofs_uakey uakey_ent;

	silofs_uakey_setup_by(&uakey_ent, &uaent->uaddr);
	return uakey_isequal(uakey, &uakey_ent);
}

static struct silofs_uaent *uaent_unconst(const struct silofs_uaent *uae)
{
	union {
		const struct silofs_uaent *p;
		struct silofs_uaent *q;
	} u = { .p = uae };
	return u.q;
}

static struct silofs_uaent *
uaent_from_htb_lh(const struct silofs_list_head *lh)
{
	const struct silofs_uaent *uae = NULL;

	uae = container_of2(lh, struct silofs_uaent, htb_lh);
	return uaent_unconst(uae);
}

static struct silofs_uaent *
uaent_from_lru_lh(const struct silofs_list_head *lh)
{
	const struct silofs_uaent *uae = NULL;

	uae = container_of2(lh, struct silofs_uaent, lru_lh);
	return uaent_unconst(uae);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_uamap_init(struct silofs_uamap *uamap, struct silofs_alloc *alloc)
{
	const unsigned int cap = 8191; /* TODO: cap based on memory size */

	listq_init(&uamap->uam_lru);
	uamap->uam_alloc = alloc;
	uamap->uam_htbl_sz = 0;
	uamap->uam_htbl_cap = 0;
	uamap->uam_htbl = silofs_lista_new(alloc, cap);
	if (uamap->uam_htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	uamap->uam_htbl_cap = cap;
	return 0;
}

void silofs_uamap_fini(struct silofs_uamap *uamap)
{
	struct silofs_alloc *alloc = uamap->uam_alloc;

	silofs_uamap_drop_all(uamap);
	silofs_lista_del(uamap->uam_htbl, uamap->uam_htbl_cap, alloc);
	listq_fini(&uamap->uam_lru);
	uamap->uam_alloc = NULL;
	uamap->uam_htbl_sz = 0;
	uamap->uam_htbl_cap = 0;
	uamap->uam_htbl = NULL;
}

static size_t uamap_slot_of(const struct silofs_uamap *uamap,
                            const struct silofs_uakey *uakey)
{
	const uint64_t hval = uakey_hash(uakey);
	const uint32_t hval32 = (uint32_t)(hval ^ (hval >> 19) ^ (hval >> 37));

	return hval32 % uamap->uam_htbl_cap;
}

static struct silofs_list_head *uamap_list_of(const struct silofs_uamap *uamap,
                                              const struct silofs_uakey *uakey)
{
	const size_t slot = uamap_slot_of(uamap, uakey);
	const struct silofs_list_head *lh = &uamap->uam_htbl[slot];

	return silofs_unconst(lh);
}

static struct silofs_list_head *
uamap_list_of_uaddr(const struct silofs_uamap *uamap,
                    const struct silofs_uaddr *uaddr)
{
	struct silofs_uakey uakey;

	silofs_uakey_setup_by(&uakey, uaddr);
	return uamap_list_of(uamap, &uakey);
}

static struct silofs_uaent *
uamap_find(const struct silofs_uamap *uamap, const struct silofs_uakey *uakey)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_uaent *uae = NULL;

	lst = uamap_list_of(uamap, uakey);
	itr = lst->next;
	while (itr != lst) {
		silofs_panic_if_null(itr);
		uae = uaent_from_htb_lh(itr);
		if (uaent_has_mapping(uae, uakey)) {
			return uaent_unconst(uae);
		}
		itr = itr->next;
	}
	return NULL;
}

const struct silofs_uaddr *
silofs_uamap_lookup(const struct silofs_uamap *uamap,
                    const struct silofs_uakey *uakey)
{
	const struct silofs_uaent *uaent;

	uaent = uamap_find(uamap, uakey);
	return (uaent != NULL) ? &uaent->uaddr : NULL;
}

static void
uamap_insert_to_lru(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	listq_push_front(&uamap->uam_lru, &uaent->lru_lh);
}

static void
uamap_remove_from_lru(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	listq_remove(&uamap->uam_lru, &uaent->lru_lh);
}

static void
uamap_insert_to_htbl(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	struct silofs_list_head *lst;

	lst = uamap_list_of_uaddr(uamap, &uaent->uaddr);
	list_push_front(lst, &uaent->htb_lh);
	uamap->uam_htbl_sz++;
}

static void
uamap_remove_from_htbl(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	list_head_remove(&uaent->htb_lh);
	uamap->uam_htbl_sz--;
}

static void
uamap_remove(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	uamap_remove_from_htbl(uamap, uaent);
	uamap_remove_from_lru(uamap, uaent);
}

static void
uamap_remove_del(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	uamap_remove(uamap, uaent);
	uaent_del(uaent, uamap->uam_alloc);
}

void silofs_uamap_remove(struct silofs_uamap *uamap,
                         const struct silofs_uakey *uakey)
{
	struct silofs_uaent *uaent;

	uaent = uamap_find(uamap, uakey);
	while (uaent != NULL) {
		uamap_remove_del(uamap, uaent);
		uaent = uamap_find(uamap, uakey);
	}
}

static struct silofs_uaent *uamap_get_lru(struct silofs_uamap *uamap)
{
	struct silofs_uaent *uae = NULL;
	struct silofs_list_head *lh;

	lh = listq_back(&uamap->uam_lru);
	if (lh != NULL) {
		uae = uaent_from_lru_lh(lh);
	}
	return uae;
}

static void
uamap_insert(struct silofs_uamap *uamap, struct silofs_uaent *uaent)
{
	uamap_insert_to_lru(uamap, uaent);
	uamap_insert_to_htbl(uamap, uaent);
}

static int uamap_remove_lru(struct silofs_uamap *uamap)
{
	struct silofs_uaent *uaent;

	uaent = uamap_get_lru(uamap);
	if (uaent == NULL) {
		return -SILOFS_ENOENT;
	}
	uamap_remove_del(uamap, uaent);
	return 0;
}

static void uamap_refresh(struct silofs_uamap *uamap)
{
	if ((2 * uamap->uam_lru.sz) > uamap->uam_htbl_cap) {
		uamap_remove_lru(uamap);
	}
}

int silofs_uamap_insert(struct silofs_uamap *uamap,
                        const struct silofs_uaddr *uaddr)
{
	struct silofs_uaent *uaent;

	uaent = uaent_new(uamap->uam_alloc, uaddr);
	if (uaent == NULL) {
		return -SILOFS_ENOMEM;
	}
	uamap_refresh(uamap);
	uamap_insert(uamap, uaent);
	return 0;
}

void silofs_uamap_drop_all(struct silofs_uamap *uamap)
{
	bool keep_drop = true;

	while (keep_drop) {
		keep_drop = silofs_uamap_drop_lru(uamap);
	}
}

bool silofs_uamap_drop_lru(struct silofs_uamap *uamap)
{
	return (uamap_remove_lru(uamap) == 0);
}
