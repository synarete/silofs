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
#include <silofs/types.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include "uidgid.h"
#include "idsmap.h"

enum {
	SILOFS_IDSMAP_HCAP = 509,
};

/* in-memory host <--> silofs user-id mapping entry */
struct silofs_umap_entry {
	struct silofs_list_head um_htof_lh;
	struct silofs_list_head um_ftoh_lh;
	struct silofs_uids um_uids;
};

/* in-memory host <--> silofs group-id mapping entry */
struct silofs_gmap_entry {
	struct silofs_list_head gm_htof_lh;
	struct silofs_list_head gm_ftoh_lh;
	struct silofs_gids gm_gids;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_umap_entry *
unconst_ume(const struct silofs_umap_entry *ume)
{
	union {
		const struct silofs_umap_entry *p;
		struct silofs_umap_entry *q;
	} u = { .p = ume };
	return u.q;
}

static struct silofs_umap_entry *
ume_by_htof_lh(const struct silofs_list_head *lh)
{
	const struct silofs_umap_entry *ume;

	ume = container_of2(lh, struct silofs_umap_entry, um_htof_lh);
	return unconst_ume(ume);
}

static struct silofs_umap_entry *
ume_by_ftoh_lh(const struct silofs_list_head *lh)
{
	const struct silofs_umap_entry *ume;

	ume = container_of2(lh, struct silofs_umap_entry, um_ftoh_lh);
	return unconst_ume(ume);
}

static void
ume_init(struct silofs_umap_entry *ume, uid_t host_uid, uid_t fs_uid)
{
	list_head_init(&ume->um_htof_lh);
	list_head_init(&ume->um_ftoh_lh);
	ume->um_uids.host_uid = host_uid;
	ume->um_uids.fs_uid   = fs_uid;
}

static void ume_fini(struct silofs_umap_entry *ume)
{
	list_head_fini(&ume->um_htof_lh);
	list_head_fini(&ume->um_ftoh_lh);
	ume->um_uids.host_uid = silofs_uid_null();
	ume->um_uids.fs_uid   = silofs_uid_null();
}

static struct silofs_umap_entry *
ume_new(struct silofs_alloc *alloc, uid_t host_uid, uid_t fs_uid)
{
	struct silofs_umap_entry *ume;

	ume = silofs_memalloc(alloc, sizeof(*ume), 0);
	if (ume != nullptr) {
		ume_init(ume, host_uid, fs_uid);
	}
	return ume;
}

static void ume_del(struct silofs_umap_entry *ume, struct silofs_alloc *alloc)
{
	ume_fini(ume);
	silofs_memfree(alloc, ume, sizeof(*ume), 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gmap_entry *
unconst_gme(const struct silofs_gmap_entry *gme)
{
	union {
		const struct silofs_gmap_entry *p;
		struct silofs_gmap_entry *q;
	} u = { .p = gme };
	return u.q;
}

static struct silofs_gmap_entry *
gme_by_htof_lh(const struct silofs_list_head *lh)
{
	const struct silofs_gmap_entry *gme;

	gme = container_of2(lh, struct silofs_gmap_entry, gm_htof_lh);
	return unconst_gme(gme);
}

static struct silofs_gmap_entry *
gme_by_ftoh_lh(const struct silofs_list_head *lh)
{
	const struct silofs_gmap_entry *gme;

	gme = container_of2(lh, struct silofs_gmap_entry, gm_ftoh_lh);
	return unconst_gme(gme);
}

static void
gme_init(struct silofs_gmap_entry *gme, gid_t host_gid, gid_t fs_gid)
{
	list_head_init(&gme->gm_htof_lh);
	list_head_init(&gme->gm_ftoh_lh);
	gme->gm_gids.host_gid = host_gid;
	gme->gm_gids.fs_gid   = fs_gid;
}

static void gme_fini(struct silofs_gmap_entry *gme)
{
	list_head_fini(&gme->gm_htof_lh);
	list_head_fini(&gme->gm_ftoh_lh);
	gme->gm_gids.host_gid = silofs_gid_null();
	gme->gm_gids.fs_gid   = silofs_gid_null();
}

static struct silofs_gmap_entry *
gme_new(struct silofs_alloc *alloc, gid_t host_gid, gid_t fs_gid)
{
	struct silofs_gmap_entry *gme;

	gme = silofs_memalloc(alloc, sizeof(*gme), 0);
	if (gme != nullptr) {
		gme_init(gme, host_gid, fs_gid);
	}
	return gme;
}

static void gme_del(struct silofs_gmap_entry *gme, struct silofs_alloc *alloc)
{
	gme_fini(gme);
	silofs_memfree(alloc, gme, sizeof(*gme), 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int idsmap_init_uhmaps(struct silofs_idsmap *idsm)
{
	struct silofs_list_head *uhtof = nullptr;
	struct silofs_list_head *uftoh = nullptr;
	const size_t hcap              = SILOFS_IDSMAP_HCAP;

	idsm->idm_uhtof = nullptr;
	idsm->idm_uftoh = nullptr;
	idsm->idm_uhcap = 0;
	idsm->idm_usize = 0;

	uhtof = silofs_lista_new(idsm->idm_alloc, hcap);
	if (uhtof == nullptr) {
		return -SILOFS_ENOMEM;
	}
	uftoh = silofs_lista_new(idsm->idm_alloc, hcap);
	if (uftoh == nullptr) {
		silofs_lista_del(uhtof, hcap, idsm->idm_alloc);
		return -SILOFS_ENOMEM;
	}

	idsm->idm_uhtof = uhtof;
	idsm->idm_uftoh = uftoh;
	idsm->idm_uhcap = hcap;
	return 0;
}

static void idsmap_fini_uhmaps(struct silofs_idsmap *idsm)
{
	silofs_lista_del(idsm->idm_uhtof, idsm->idm_uhcap, idsm->idm_alloc);
	silofs_lista_del(idsm->idm_uftoh, idsm->idm_uhcap, idsm->idm_alloc);
	idsm->idm_uhtof = nullptr;
	idsm->idm_uftoh = nullptr;
	idsm->idm_uhcap = 0;
	idsm->idm_usize = 0;
}

static int idsmap_init_ghmaps(struct silofs_idsmap *idsm)
{
	struct silofs_list_head *ghtof = nullptr;
	struct silofs_list_head *gftoh = nullptr;
	const size_t hcap              = SILOFS_IDSMAP_HCAP;

	idsm->idm_ghtof = nullptr;
	idsm->idm_gftoh = nullptr;
	idsm->idm_ghcap = 0;
	idsm->idm_gsize = 0;

	ghtof = silofs_lista_new(idsm->idm_alloc, hcap);
	if (ghtof == nullptr) {
		return -SILOFS_ENOMEM;
	}
	gftoh = silofs_lista_new(idsm->idm_alloc, hcap);
	if (gftoh == nullptr) {
		silofs_lista_del(ghtof, hcap, idsm->idm_alloc);
		return -SILOFS_ENOMEM;
	}

	idsm->idm_ghtof = ghtof;
	idsm->idm_gftoh = gftoh;
	idsm->idm_ghcap = hcap;
	return 0;
}

static void idsmap_fini_ghmaps(struct silofs_idsmap *idsm)
{
	silofs_lista_del(idsm->idm_ghtof, idsm->idm_ghcap, idsm->idm_alloc);
	silofs_lista_del(idsm->idm_gftoh, idsm->idm_ghcap, idsm->idm_alloc);
	idsm->idm_ghtof = nullptr;
	idsm->idm_gftoh = nullptr;
	idsm->idm_ghcap = 0;
	idsm->idm_gsize = 0;
}

static int idsmap_init_hmaps(struct silofs_idsmap *idsm)
{
	int err;

	err = idsmap_init_uhmaps(idsm);
	if (err) {
		return err;
	}
	err = idsmap_init_ghmaps(idsm);
	if (err) {
		idsmap_fini_uhmaps(idsm);
		return err;
	}
	return 0;
}

static void idsmap_fini_hmaps(struct silofs_idsmap *idsm)
{
	idsmap_fini_uhmaps(idsm);
	idsmap_fini_ghmaps(idsm);
}

int silofs_idsmap_init(struct silofs_idsmap *idsm, struct silofs_alloc *alloc)
{
	silofs_memzero(idsm, sizeof(*idsm));
	idsm->idm_alloc         = alloc;
	idsm->idm_allow_hostids = false;
	return idsmap_init_hmaps(idsm);
}

void silofs_idsmap_fini(struct silofs_idsmap *idsm)
{
	silofs_idsmap_clear(idsm);
	idsmap_fini_hmaps(idsm);
	idsm->idm_alloc = nullptr;
}

static int idsmap_noent_status(const struct silofs_idsmap *idsm)
{
	return idsm->idm_allow_hostids ? 0 : -SILOFS_ENOENT;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_umap_entry *
idsmap_new_ume(const struct silofs_idsmap *idsm, uid_t host_uid, uid_t fs_uid)
{
	return ume_new(idsm->idm_alloc, host_uid, fs_uid);
}

static void
idsmap_del_ume(const struct silofs_idsmap *idsm, struct silofs_umap_entry *ume)
{
	ume_del(ume, idsm->idm_alloc);
}

static size_t idsmap_umap_slot_of(const struct silofs_idsmap *idsm, uid_t uid)
{
	return uid % idsm->idm_uhcap;
}

static struct silofs_list_head *
idsmap_uhtof_bin_at(const struct silofs_idsmap *idsm, size_t slot)
{
	return &idsm->idm_uhtof[slot];
}

static struct silofs_list_head *
idsmap_uftoh_bin_at(const struct silofs_idsmap *idsm, size_t slot)
{
	return &idsm->idm_uftoh[slot];
}

static struct silofs_list_head *
idsmap_uhtof_bin_of(const struct silofs_idsmap *idsm, uid_t host_uid)
{
	const size_t slot = idsmap_umap_slot_of(idsm, host_uid);

	return idsmap_uhtof_bin_at(idsm, slot);
}

static struct silofs_list_head *
idsmap_uftoh_bin_of(const struct silofs_idsmap *idsm, uid_t host_uid)
{
	const size_t slot = idsmap_umap_slot_of(idsm, host_uid);

	return idsmap_uftoh_bin_at(idsm, slot);
}

static int
idsmap_insert_umap(struct silofs_idsmap *idsm, uid_t host_uid, uid_t fs_uid)
{
	struct silofs_umap_entry *ume = nullptr;
	struct silofs_list_head *lst  = nullptr;

	ume = idsmap_new_ume(idsm, host_uid, fs_uid);
	if (ume == nullptr) {
		return -SILOFS_ENOMEM;
	}

	lst = idsmap_uhtof_bin_of(idsm, host_uid);
	list_head_insert_after(lst, &ume->um_htof_lh);

	lst = idsmap_uftoh_bin_of(idsm, fs_uid);
	list_head_insert_after(lst, &ume->um_ftoh_lh);

	idsm->idm_usize++;

	return 0;
}

static void idsmap_clear_umap_at(struct silofs_idsmap *idsm, size_t slot)
{
	struct silofs_umap_entry *ume;
	struct silofs_list_head *itr;
	struct silofs_list_head *lst;

	lst = idsmap_uhtof_bin_at(idsm, slot);
	itr = lst->next;
	while (itr != lst) {
		silofs_assert_gt(idsm->idm_usize, 0);

		ume = ume_by_htof_lh(itr);
		itr = itr->next;

		list_head_remove(&ume->um_htof_lh);
		list_head_remove(&ume->um_ftoh_lh);
		idsmap_del_ume(idsm, ume);
		idsm->idm_usize--;
	}
}

static void idsmap_clear_umap(struct silofs_idsmap *idsm)
{
	for (size_t slot = 0; slot < idsm->idm_uhcap; ++slot) {
		idsmap_clear_umap_at(idsm, slot);
	}
	silofs_assert_eq(idsm->idm_usize, 0);
}

static const struct silofs_umap_entry *
idsmap_lookup_uhtof(const struct silofs_idsmap *idsm, uid_t host_uid)
{
	const struct silofs_umap_entry *ume;
	const struct silofs_list_head *itr;
	const struct silofs_list_head *lst;

	lst = idsmap_uhtof_bin_of(idsm, host_uid);
	itr = lst->next;
	while (itr != lst) {
		silofs_assert_gt(idsm->idm_usize, 0);

		ume = ume_by_htof_lh(itr);
		if (ume->um_uids.host_uid == host_uid) {
			return ume;
		}
		itr = itr->next;
	}
	return nullptr;
}

static const struct silofs_umap_entry *
idsmap_lookup_uftoh(const struct silofs_idsmap *idsm, uid_t fs_uid)
{
	const struct silofs_umap_entry *ume;
	const struct silofs_list_head *itr;
	const struct silofs_list_head *lst;

	lst = idsmap_uftoh_bin_of(idsm, fs_uid);
	itr = lst->next;
	while (itr != lst) {
		silofs_assert_gt(idsm->idm_usize, 0);

		ume = ume_by_ftoh_lh(itr);
		if (ume->um_uids.fs_uid == fs_uid) {
			return ume;
		}
		itr = itr->next;
	}
	return nullptr;
}

static int idsmap_resolve_uhtof(const struct silofs_idsmap *idsm,
                                uid_t host_uid, uid_t *out_fs_uid)
{
	const struct silofs_umap_entry *ume;
	int ret;

	ume = idsmap_lookup_uhtof(idsm, host_uid);
	if (ume != nullptr) {
		*out_fs_uid = ume->um_uids.fs_uid;
		ret         = 0;
	} else {
		*out_fs_uid = host_uid;
		ret         = idsmap_noent_status(idsm);
	}
	return ret;
}

static int idsmap_resolve_uftoh(const struct silofs_idsmap *idsm, uid_t fs_uid,
                                uid_t *out_host_uid)
{
	const struct silofs_umap_entry *ume;
	int ret;

	ume = idsmap_lookup_uftoh(idsm, fs_uid);
	if (ume != nullptr) {
		*out_host_uid = ume->um_uids.host_uid;
		ret           = 0;
	} else {
		*out_host_uid = fs_uid;
		ret           = idsmap_noent_status(idsm);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gmap_entry *
idsmap_new_gme(const struct silofs_idsmap *idsm, gid_t host_gid, gid_t fs_gid)
{
	return gme_new(idsm->idm_alloc, host_gid, fs_gid);
}

static void
idsmap_del_gme(const struct silofs_idsmap *idsm, struct silofs_gmap_entry *gme)
{
	gme_del(gme, idsm->idm_alloc);
}

static size_t idsmap_gmap_slot_of(const struct silofs_idsmap *idsm, gid_t gid)
{
	return gid % idsm->idm_ghcap;
}

static struct silofs_list_head *
idsmap_ghtof_bin_at(const struct silofs_idsmap *idsm, size_t slot)
{
	return &idsm->idm_ghtof[slot];
}

static struct silofs_list_head *
idsmap_gftoh_bin_at(const struct silofs_idsmap *idsm, size_t slot)
{
	return &idsm->idm_gftoh[slot];
}

static struct silofs_list_head *
idsmap_ghtof_bin_of(const struct silofs_idsmap *idsm, gid_t host_gid)
{
	const size_t slot = idsmap_gmap_slot_of(idsm, host_gid);

	return idsmap_ghtof_bin_at(idsm, slot);
}

static struct silofs_list_head *
idsmap_gftoh_bin_of(const struct silofs_idsmap *idsm, gid_t host_gid)
{
	const size_t slot = idsmap_gmap_slot_of(idsm, host_gid);

	return idsmap_gftoh_bin_at(idsm, slot);
}

static int
idsmap_insert_gmap(struct silofs_idsmap *idsm, gid_t host_gid, gid_t fs_gid)
{
	struct silofs_gmap_entry *gme = nullptr;
	struct silofs_list_head *lst  = nullptr;

	gme = idsmap_new_gme(idsm, host_gid, fs_gid);
	if (gme == nullptr) {
		return -SILOFS_ENOMEM;
	}

	lst = idsmap_ghtof_bin_of(idsm, host_gid);
	list_head_insert_after(lst, &gme->gm_htof_lh);

	lst = idsmap_gftoh_bin_of(idsm, fs_gid);
	list_head_insert_after(lst, &gme->gm_ftoh_lh);

	idsm->idm_gsize++;

	return 0;
}

static void idsmap_clear_gmap_at(struct silofs_idsmap *idsm, size_t slot)
{
	struct silofs_gmap_entry *gme;
	struct silofs_list_head *itr;
	struct silofs_list_head *lst;

	lst = idsmap_ghtof_bin_at(idsm, slot);
	itr = lst->next;
	while (itr != lst) {
		silofs_panic_if_null(itr);
		silofs_assert_gt(idsm->idm_gsize, 0);

		gme = gme_by_htof_lh(itr);
		itr = itr->next;

		list_head_remove(&gme->gm_htof_lh);
		list_head_remove(&gme->gm_ftoh_lh);
		idsmap_del_gme(idsm, gme);
		idsm->idm_gsize--;
	}
}

static void idsmap_clear_gmap(struct silofs_idsmap *idsm)
{
	for (size_t slot = 0; slot < idsm->idm_ghcap; ++slot) {
		idsmap_clear_gmap_at(idsm, slot);
	}
	silofs_assert_eq(idsm->idm_gsize, 0);
}

static const struct silofs_gmap_entry *
idsmap_lookup_ghtof(const struct silofs_idsmap *idsm, gid_t host_gid)
{
	const struct silofs_gmap_entry *gme;
	const struct silofs_list_head *itr;
	const struct silofs_list_head *lst;

	lst = idsmap_ghtof_bin_of(idsm, host_gid);
	itr = lst->next;
	while (itr != lst) {
		silofs_panic_if_null(itr);
		silofs_assert_gt(idsm->idm_gsize, 0);

		gme = gme_by_htof_lh(itr);
		if (gme->gm_gids.host_gid == host_gid) {
			return gme;
		}
		itr = itr->next;
	}
	return nullptr;
}

static const struct silofs_gmap_entry *
idsmap_lookup_gftoh(const struct silofs_idsmap *idsm, gid_t fs_gid)
{
	const struct silofs_gmap_entry *gme;
	const struct silofs_list_head *itr;
	const struct silofs_list_head *lst;

	lst = idsmap_gftoh_bin_of(idsm, fs_gid);
	itr = lst->next;
	while (itr != lst) {
		silofs_panic_if_null(itr);
		silofs_assert_gt(idsm->idm_gsize, 0);

		gme = gme_by_ftoh_lh(itr);
		if (gme->gm_gids.fs_gid == fs_gid) {
			return gme;
		}
		itr = itr->next;
	}
	return nullptr;
}

static int idsmap_resolve_ghtof(const struct silofs_idsmap *idsm,
                                gid_t host_gid, gid_t *out_fs_gid)
{
	const struct silofs_gmap_entry *gme;
	int ret;

	gme = idsmap_lookup_ghtof(idsm, host_gid);
	if (gme != nullptr) {
		*out_fs_gid = gme->gm_gids.fs_gid;
		ret         = 0;
	} else {
		*out_fs_gid = host_gid;
		ret         = idsmap_noent_status(idsm);
	}
	return ret;
}

static int idsmap_resolve_gftoh(const struct silofs_idsmap *idsm, gid_t fs_gid,
                                gid_t *out_host_gid)
{
	const struct silofs_gmap_entry *gme;
	int ret;

	gme = idsmap_lookup_gftoh(idsm, fs_gid);
	if (gme != nullptr) {
		*out_host_gid = gme->gm_gids.host_gid;
		ret           = 0;
	} else {
		*out_host_gid = fs_gid;
		ret           = idsmap_noent_status(idsm);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
idsmap_add_uid(struct silofs_idsmap *idsm, const struct silofs_uids *uid)
{
	return idsmap_insert_umap(idsm, uid->host_uid, uid->fs_uid);
}

static int idsmap_populate_uids(struct silofs_idsmap *idsm,
                                const struct silofs_fsids *fsids)
{
	int err;

	for (size_t i = 0; i < fsids->users.nuids; ++i) {
		err = idsmap_add_uid(idsm, &fsids->users.uids[i]);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int
idsmap_add_gid(struct silofs_idsmap *idsm, const struct silofs_gids *gid)
{
	return idsmap_insert_gmap(idsm, gid->host_gid, gid->fs_gid);
}

static int idsmap_populate_gids(struct silofs_idsmap *idsm,
                                const struct silofs_fsids *fsids)
{
	int err;

	for (size_t j = 0; j < fsids->groups.ngids; ++j) {
		err = idsmap_add_gid(idsm, &fsids->groups.gids[j]);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_idsmap_populate(struct silofs_idsmap *idsm,
                           const struct silofs_fsids *fsids,
                           bool allow_hostids)
{
	int err;

	err = idsmap_populate_uids(idsm, fsids);
	if (err) {
		return err;
	}
	err = idsmap_populate_gids(idsm, fsids);
	if (err) {
		return err;
	}
	idsm->idm_allow_hostids = allow_hostids;
	return 0;
}

void silofs_idsmap_clear(struct silofs_idsmap *idsm)
{
	idsmap_clear_umap(idsm);
	idsmap_clear_gmap(idsm);
}

int silofs_idsmap_mapcreds(const struct silofs_idsmap *idsm, uid_t host_uid,
                           gid_t host_gid, uid_t *out_fs_uid,
                           gid_t *out_fs_gid)
{
	int err;

	*out_fs_uid = host_uid;
	*out_fs_gid = host_gid;

	if (!silofs_uid_isnull(host_uid)) {
		err = idsmap_resolve_uhtof(idsm, host_uid, out_fs_uid);
		if (err) {
			return err;
		}
	}
	if (!silofs_gid_isnull(host_gid)) {
		err = idsmap_resolve_ghtof(idsm, host_gid, out_fs_gid);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_idsmap_rmapcreds(const struct silofs_idsmap *idsm, uid_t fs_uid,
                            gid_t fs_gid, uid_t *out_host_uid,
                            gid_t *out_host_gid)
{
	int err;

	*out_host_uid = fs_uid;
	*out_host_gid = fs_gid;

	if (!silofs_uid_isnull(fs_uid)) {
		err = idsmap_resolve_uftoh(idsm, fs_uid, out_host_uid);
		if (err) {
			return err;
		}
	}
	if (!silofs_gid_isnull(fs_gid)) {
		err = idsmap_resolve_gftoh(idsm, fs_gid, out_host_gid);
		if (err) {
			return err;
		}
	}
	return 0;
}
