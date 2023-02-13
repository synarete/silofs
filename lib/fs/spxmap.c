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


/* single entry of free vspace */
struct silofs_spa_entry {
	struct silofs_avl_node  spe_an;
	loff_t                  spe_voff;
	size_t                  spe_len;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void splifo_clear(struct silofs_splifo *spl)
{
	silofs_memzero(spl->spl_lifo, sizeof(spl->spl_lifo));
	spl->spl_size = 0;
}

static void splifo_init(struct silofs_splifo *spl, unsigned int ulen)
{
	splifo_clear(spl);
	spl->spl_ulen = ulen;
}

static void splifo_fini(struct silofs_splifo *spl)
{
	splifo_clear(spl);
}

static int splifo_pop_vspace(struct silofs_splifo *spl,
                             size_t len, loff_t *out_off)
{
	if (!spl->spl_size || (spl->spl_ulen != len)) {
		return -ENOENT;
	}
	*out_off = spl->spl_lifo[spl->spl_size - 1];
	spl->spl_size--;
	return 0;
}

static int splifo_add_vspace(struct silofs_splifo *spl, loff_t off, size_t len)
{
	const size_t size_max = ARRAY_SIZE(spl->spl_lifo);

	if (!(spl->spl_size < size_max) || (spl->spl_ulen != len)) {
		return -ENOSPC;
	}
	spl->spl_lifo[spl->spl_size] = off;
	spl->spl_size++;
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

	spe = silofs_allocate(alloc, sizeof(*spe));
	if (spe != NULL) {
		spe_init(spe, voff, len);
	}
	return spe;
}

static void spe_del(struct silofs_spa_entry *spe,
                    struct silofs_alloc *alloc)
{
	spe_fini(spe);
	silofs_deallocate(alloc, spe, sizeof(*spe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static unsigned int spamap_capacity(enum silofs_stype stype)
{
	const uint32_t mega = SILOFS_MEGA;
	const uint32_t nmul = stype_isdata(stype) ? 16 : 4;

	return (nmul * mega);
}

static struct silofs_spa_entry *
spamap_new_spe(struct silofs_spamap *spa, loff_t voff, size_t len)
{
	struct silofs_spa_entry *spe;

	spe = spe_new(voff, len, spa->spa_alloc);
	return spe;
}

static void spamap_delete_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
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

static void
spmap_find_next_prev(const struct silofs_spamap *spa, loff_t off,
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

static void spamap_insert_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_insert(avl, an);
}

static void spamap_remove_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_remove(avl, an);
}

static void spamap_evict_spe(struct silofs_spamap *spa,
                             struct silofs_spa_entry *spe)
{
	spamap_remove_spe(spa, spe);
	spamap_delete_spe(spa, spe);
}

static int spamap_check_cap_add(const struct silofs_spamap *spa)
{
	const size_t spe_size = sizeof(struct silofs_spa_entry);
	const size_t cap_cur = spa->spa_avl.size * spe_size;
	const size_t cap_max = spa->spa_cap_max;

	return (cap_cur < cap_max) ? 0 : -ENOMEM;
}

static int spamap_pop_vspace(struct silofs_spamap *spa,
                             size_t len, loff_t *out_off)
{
	struct silofs_spa_entry *spe;
	int err;

	err = splifo_pop_vspace(&spa->spa_lifo, len, out_off);
	if (!err) {
		return 0;
	}
	spe = spamap_minimal_spe(spa);
	if (spe == NULL) {
		return -ENOSPC;
	}
	if (len > spe->spe_len) {
		return -ENOSPC;
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

static int spamap_merge_vspace(struct silofs_spamap *spa,
                               loff_t off, size_t len)
{
	struct silofs_spa_entry *spe = NULL;
	struct silofs_spa_entry *spe_prev = NULL;
	struct silofs_spa_entry *spe_next = NULL;
	loff_t end;
	int ret = -ENOENT;

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
			return -ENOMEM;
		}
		spamap_insert_spe(spa, spe);
	} else {
		/* full merge (prev + next ) */
		spe->spe_len += spe_next->spe_len;
		spamap_evict_spe(spa, spe_next);
	}
	return 0;
}

static int spamap_insert_vspace(struct silofs_spamap *spa,
                                loff_t off, size_t len)
{
	struct silofs_spa_entry *spe;
	struct silofs_spa_entry *spe_max = NULL;

	spe = spamap_new_spe(spa, off, len);
	if (spe != NULL) {
		goto out_ok; /* trivial case */
	}
	spe_max = spamap_maximal_spe(spa);
	if (spe_max == NULL) {
		return -ENOMEM;
	}
	if (off > spe_max->spe_voff) {
		return -ENOMEM;
	}
	spamap_delete_spe(spa, spe_max);
	spe = spamap_new_spe(spa, off, len);
	if (spe == NULL) {
		return -ENOMEM;
	}
out_ok:
	spamap_insert_spe(spa, spe);
	return 0;
}

static int spamap_add_vspace(struct silofs_spamap *spa, loff_t off, size_t len)
{
	int err;

	err = splifo_add_vspace(&spa->spa_lifo, off, len);
	if (!err) {
		return 0;
	}
	err = spamap_merge_vspace(spa, off, len);
	if (err != -ENOENT) {
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

static int spamap_find_baseof(const struct silofs_spamap *spa,
                              loff_t off, loff_t *out_base_off)
{
	struct silofs_spa_entry *spe;

	spe = spmap_lower_bound_spe(spa, off);
	if (spe == NULL) {
		return -ENOENT;
	}
	spe = spmap_prev_of(spa, spe);
	if (spe == NULL) {
		return -ENOENT;
	}
	if (!spe_is_within(spe, off)) {
		return -ENOENT;
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
	splifo_clear(&spa->spa_lifo);
}

static void spamap_init(struct silofs_spamap *spa, enum silofs_stype stype,
                        struct silofs_alloc *alloc)
{
	splifo_init(&spa->spa_lifo, (unsigned int)stype_size(stype));
	silofs_avl_init(&spa->spa_avl, spe_getkey, voff_compare, spa);
	spa->spa_alloc = alloc;
	spa->spa_cap_max = spamap_capacity(stype);
	spa->spa_stype = stype;
}

static void spamap_fini(struct silofs_spamap *spa)
{
	splifo_fini(&spa->spa_lifo);
	silofs_avl_fini(&spa->spa_avl);
	spa->spa_alloc = NULL;
	spa->spa_cap_max = 0;
	spa->spa_stype = SILOFS_STYPE_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spamap *
spamaps_sub_map(struct silofs_spamaps *spam, enum silofs_stype stype)
{
	struct silofs_spamap *ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		ret = &spam->spa_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		ret = &spam->spa_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		ret = &spam->spa_databk;
		break;
	case SILOFS_STYPE_INODE:
		ret = &spam->spa_inode;
		break;
	case SILOFS_STYPE_XANODE:
		ret = &spam->spa_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		ret = &spam->spa_dtnode;
		break;
	case SILOFS_STYPE_FTNODE:
		ret = &spam->spa_ftnode;
		break;
	case SILOFS_STYPE_SYMVAL:
		ret = &spam->spa_symval;
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_RESERVED:
	case SILOFS_STYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static const struct silofs_spamap *
spamaps_sub_map2(const struct silofs_spamaps *spam, enum silofs_stype stype)
{
	return spamaps_sub_map(unconst(spam), stype);
}

int silofs_spamaps_store(struct silofs_spamaps *spam,
                         enum silofs_stype stype, loff_t voff, size_t len)
{
	struct silofs_spamap *spa;
	int err = -EINVAL;

	spa = spamaps_sub_map(spam, stype);
	if (spa != NULL) {
		err = spamap_add_vspace(spa, voff, len);
	}
	return err;
}

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_stype stype,
                          size_t len, loff_t *out_voff)
{
	struct silofs_spamap *spa;
	int err = -EINVAL;

	spa = spamaps_sub_map(spam, stype);
	if (spa != NULL) {
		err = spamap_pop_vspace(spa, len, out_voff);
	}
	return err;
}

int silofs_spamaps_baseof(const struct silofs_spamaps *spam,
                          enum silofs_stype stype, loff_t voff, loff_t *out)
{
	const struct silofs_spamap *spa;
	int err = -ENOENT;

	spa = spamaps_sub_map2(spam, stype);
	if (spa != NULL) {
		err = spamap_find_baseof(spa, voff, out);
	}
	return err;
}

void silofs_spamaps_drop(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_clear(spa);
		}
	}
}

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc *alloc)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_init(spa, stype, alloc);
		}
	}
	return 0;
}

void silofs_spamaps_fini(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_clear(spa);
			spamap_fini(spa);
		}
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static enum silofs_stype uaddr_vspace(const struct silofs_uaddr *uaddr)
{
	return uaddr->oaddr.bka.blobid.vspace;
}

void silofs_uakey_setup(struct silofs_uakey *uakey, loff_t voff,
                        enum silofs_height height, enum silofs_stype vspace)
{
	uakey->voff = voff;
	uakey->height = height;
	uakey->vspace = vspace;
}

void silofs_uakey_setup_by(struct silofs_uakey *uakey,
                           const struct silofs_uaddr *uaddr)
{
	silofs_uakey_setup(uakey, uaddr->voff,
	                   uaddr->height, uaddr_vspace(uaddr));
}

void silofs_uakey_setup_by2(struct silofs_uakey *uakey,
                            const struct silofs_vrange *vrange,
                            enum silofs_stype vspace)
{
	silofs_uakey_setup(uakey, vrange->beg, vrange->height, vspace);
}

static bool uakey_isequal(const struct silofs_uakey *uakey1,
                          const struct silofs_uakey *uakey2)
{
	return ((uakey1->voff == uakey2->voff) &&
	        (uakey1->height == uakey2->height) &&
	        (uakey1->vspace == uakey2->vspace));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uaent {
	struct silofs_list_head  htb_lh;
	struct silofs_list_head  lru_lh;
	struct silofs_uaddr      uaddr;
};

static void uaent_init(struct silofs_uaent *uae,
                       const struct silofs_uaddr *uaddr)
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

	uae = silofs_allocate(alloc, sizeof(*uae));
	if (uae != NULL) {
		uaent_init(uae, uaddr);
	}
	return uae;
}

static void uaent_del(struct silofs_uaent *uae, struct silofs_alloc *alloc)
{
	uaent_fini(uae);
	silofs_deallocate(alloc, uae, sizeof(*uae));
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
	} u = {
		.p = uae
	};
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
	const unsigned int cap = 4093; /* TODO: cap based on memory size */

	listq_init(&uamap->uam_lru);
	uamap->uam_alloc = alloc;
	uamap->uam_htbl_sz = 0;
	uamap->uam_htbl_cap = 0;
	uamap->uam_htbl = silofs_lista_new(alloc, cap);
	if (uamap->uam_htbl == NULL) {
		return -ENOMEM;
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
	const uint32_t rot = (uint32_t)uakey->height & 0xF;
	const uint64_t ukey = (uint64_t)(uakey->voff + uakey->vspace);
	const uint64_t key = silofs_rotate64(ukey, rot);

	return key % uamap->uam_htbl_cap;
}

static struct silofs_list_head *
uamap_list_of(const struct silofs_uamap *uamap,
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

static void uamap_insert_to_lru(struct silofs_uamap *uamap,
                                struct silofs_uaent *uaent)
{
	listq_push_front(&uamap->uam_lru, &uaent->lru_lh);
}

static void uamap_remove_from_lru(struct silofs_uamap *uamap,
                                  struct silofs_uaent *uaent)
{
	listq_remove(&uamap->uam_lru, &uaent->lru_lh);
}

static void uamap_insert_to_htbl(struct silofs_uamap *uamap,
                                 struct silofs_uaent *uaent)
{
	struct silofs_list_head *lst;

	lst = uamap_list_of_uaddr(uamap, &uaent->uaddr);
	list_push_front(lst, &uaent->htb_lh);
	uamap->uam_htbl_sz++;
}

static void uamap_remove_from_htbl(struct silofs_uamap *uamap,
                                   struct silofs_uaent *uaent)
{
	list_head_remove(&uaent->htb_lh);
	uamap->uam_htbl_sz--;
}

static void uamap_remove(struct silofs_uamap *uamap,
                         struct silofs_uaent *uaent)
{
	uamap_remove_from_htbl(uamap, uaent);
	uamap_remove_from_lru(uamap, uaent);
}

static void uamap_remove_del(struct silofs_uamap *uamap,
                             struct silofs_uaent *uaent)
{
	uamap_remove(uamap, uaent);
	uaent_del(uaent, uamap->uam_alloc);
}

int silofs_uamap_remove(struct silofs_uamap *uamap,
                        const struct silofs_uaddr *uaddr)
{
	struct silofs_uakey uakey;
	struct silofs_uaent *uaent;

	silofs_uakey_setup_by(&uakey, uaddr);
	uaent = uamap_find(uamap, &uakey);
	if (uaent == NULL) {
		return -ENOENT;
	}
	uamap_remove_del(uamap, uaent);
	return 0;
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

static void uamap_insert(struct silofs_uamap *uamap,
                         struct silofs_uaent *uaent)
{
	uamap_insert_to_lru(uamap, uaent);
	uamap_insert_to_htbl(uamap, uaent);
}

static int uamap_remove_lru(struct silofs_uamap *uamap)
{
	struct silofs_uaent *uaent;

	uaent = uamap_get_lru(uamap);
	if (uaent == NULL) {
		return -ENOENT;
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
		return -ENOMEM;
	}
	uamap_refresh(uamap);
	uamap_insert(uamap, uaent);
	return 0;
}

void silofs_uamap_drop_all(struct silofs_uamap *uamap)
{
	bool keep_drop = true;

	while (keep_drop) {
		keep_drop = (uamap_remove_lru(uamap) == 0);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc *alloc, size_t nelems)
{
	struct silofs_list_head *lista;

	lista = silofs_allocate(alloc, sizeof(*lista) * nelems);
	if (lista != NULL) {
		list_head_initn(lista, nelems);
	}
	return lista;
}

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc *alloc)
{
	list_head_finin(lista, nelems);
	silofs_deallocate(alloc, lista, sizeof(*lista) * nelems);
}



