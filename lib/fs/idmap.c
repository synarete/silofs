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
#include <silofs/fs.h>
#include <silofs/fs-private.h>

#define IDSMAP_HCAP     (509)


/* in-memory host<-->silo uid/gid mapping entry */
struct silofs_id_entry {
	struct silofs_list_head id_lh;
	struct silofs_id        id;
};

/* in-memory host <--> silofs user-id mapping entry */
struct silofs_umap_entry {
	struct silofs_list_head um_htof_lh;
	struct silofs_list_head um_ftoh_lh;
	struct silofs_uid_map   um;
};

/* in-memory host <--> silofs group-id mapping entry */
struct silofs_gmap_entry {
	struct silofs_list_head gm_htof_lh;
	struct silofs_list_head gm_ftoh_lh;
	struct silofs_gid_map   gm;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool idt_is_uid(enum silofs_idtype idt)
{
	return (idt == SILOFS_IDTYPE_UID);
}

static bool idt_is_gid(enum silofs_idtype idt)
{
	return (idt == SILOFS_IDTYPE_GID);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_umap_entry *
unconst_ume(const struct silofs_umap_entry *ume)
{
	union {
		const struct silofs_umap_entry *p;
		struct silofs_umap_entry *q;
	} u = {
		.p = ume
	};
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

static void ume_init(struct silofs_umap_entry *ume,
                     uid_t host_uid, uid_t fs_uid)
{
	list_head_init(&ume->um_htof_lh);
	list_head_init(&ume->um_ftoh_lh);
	ume->um.host_uid = host_uid;
	ume->um.fs_uid = fs_uid;
}

static void ume_fini(struct silofs_umap_entry *ume)
{
	list_head_fini(&ume->um_htof_lh);
	list_head_fini(&ume->um_ftoh_lh);
	ume->um.host_uid = (uid_t)(-1);
	ume->um.fs_uid = (uid_t)(-1);
}

static struct silofs_umap_entry *
ume_new(struct silofs_alloc *alloc, uid_t host_uid, uid_t fs_uid)
{
	struct silofs_umap_entry *ume;

	ume = silofs_allocate(alloc, sizeof(*ume));
	if (ume != NULL) {
		ume_init(ume, host_uid, fs_uid);
	}
	return ume;
}

static void ume_del(struct silofs_umap_entry *ume, struct silofs_alloc *alloc)
{
	ume_fini(ume);
	silofs_deallocate(alloc, ume, sizeof(*ume));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gmap_entry *
unconst_gme(const struct silofs_gmap_entry *gme)
{
	union {
		const struct silofs_gmap_entry *p;
		struct silofs_gmap_entry *q;
	} u = {
		.p = gme
	};
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

static void gme_init(struct silofs_gmap_entry *gme,
                     gid_t host_gid, gid_t fs_gid)
{
	list_head_init(&gme->gm_htof_lh);
	list_head_init(&gme->gm_ftoh_lh);
	gme->gm.host_gid = host_gid;
	gme->gm.fs_gid = fs_gid;
}

static void gme_fini(struct silofs_gmap_entry *gme)
{
	list_head_fini(&gme->gm_htof_lh);
	list_head_fini(&gme->gm_ftoh_lh);
	gme->gm.host_gid = (gid_t)(-1);
	gme->gm.fs_gid = (gid_t)(-1);
}

static struct silofs_gmap_entry *
gme_new(struct silofs_alloc *alloc, gid_t host_gid, gid_t fs_gid)
{
	struct silofs_gmap_entry *gme;

	gme = silofs_allocate(alloc, sizeof(*gme));
	if (gme != NULL) {
		gme_init(gme, host_gid, fs_gid);
	}
	return gme;
}

static void gme_del(struct silofs_gmap_entry *gme, struct silofs_alloc *alloc)
{
	gme_fini(gme);
	silofs_deallocate(alloc, gme, sizeof(*gme));
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int idsmap_init_uhmaps(struct silofs_idsmap *idsm)
{
	struct silofs_list_head *uhtof = NULL;
	struct silofs_list_head *uftoh = NULL;
	const size_t hcap = IDSMAP_HCAP;

	idsm->idm_uhtof = NULL;
	idsm->idm_uftoh = NULL;
	idsm->idm_uhcap = 0;
	idsm->idm_usize = 0;

	uhtof = silofs_lista_new(idsm->idm_alloc, hcap);
	if (uhtof == NULL) {
		return -SILOFS_ENOMEM;
	}
	uftoh = silofs_lista_new(idsm->idm_alloc, hcap);
	if (uftoh == NULL) {
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
	idsm->idm_uhtof = NULL;
	idsm->idm_uftoh = NULL;
	idsm->idm_uhcap = 0;
	idsm->idm_usize = 0;
}

static int idsmap_init_ghmaps(struct silofs_idsmap *idsm)
{
	struct silofs_list_head *ghtof = NULL;
	struct silofs_list_head *gftoh = NULL;
	const size_t hcap = IDSMAP_HCAP;

	idsm->idm_ghtof = NULL;
	idsm->idm_gftoh = NULL;
	idsm->idm_ghcap = 0;
	idsm->idm_gsize = 0;

	ghtof = silofs_lista_new(idsm->idm_alloc, hcap);
	if (ghtof == NULL) {
		return -SILOFS_ENOMEM;
	}
	gftoh = silofs_lista_new(idsm->idm_alloc, hcap);
	if (gftoh == NULL) {
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
	idsm->idm_ghtof = NULL;
	idsm->idm_gftoh = NULL;
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

int silofs_idsmap_init(struct silofs_idsmap *idsm,
                       struct silofs_alloc *alloc, bool allow_hostids)
{
	silofs_memzero(idsm, sizeof(*idsm));
	idsm->idm_alloc = alloc;
	idsm->idm_allow_hotids = allow_hostids;
	return idsmap_init_hmaps(idsm);
}

void silofs_idsmap_fini(struct silofs_idsmap *idsm)
{
	silofs_idsmap_clear(idsm);
	idsmap_fini_hmaps(idsm);
	idsm->idm_alloc = NULL;
}

static int idsmap_noent_status(const struct silofs_idsmap *idsm)
{
	return idsm->idm_allow_hotids ? 0 : -SILOFS_ENOENT;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_umap_entry *
idsmap_new_ume(const struct silofs_idsmap *idsm, uid_t host_uid, uid_t fs_uid)
{
	return ume_new(idsm->idm_alloc, host_uid, fs_uid);
}

static void idsmap_del_ume(const struct silofs_idsmap *idsm,
                           struct silofs_umap_entry *ume)
{
	ume_del(ume, idsm->idm_alloc);
}

static size_t
idsmap_umap_slot_of(const struct silofs_idsmap *idsm, uid_t uid)
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

static int idsmap_insert_umap(struct silofs_idsmap *idsm,
                              uid_t host_uid, uid_t fs_uid)
{
	struct silofs_umap_entry *ume = NULL;
	struct silofs_list_head *lst = NULL;

	ume = idsmap_new_ume(idsm, host_uid, fs_uid);
	if (ume == NULL) {
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
		if (ume->um.host_uid == host_uid) {
			return ume;
		}
		itr = itr->next;
	}
	return NULL;
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
		if (ume->um.fs_uid == fs_uid) {
			return ume;
		}
		itr = itr->next;
	}
	return NULL;
}

static int idsmap_resolve_uhtof(const struct silofs_idsmap *idsm,
                                uid_t host_uid, uid_t *out_fs_uid)
{
	const struct silofs_umap_entry *ume;
	int ret;

	ume = idsmap_lookup_uhtof(idsm, host_uid);
	if (ume != NULL) {
		*out_fs_uid = ume->um.fs_uid;
		ret = 0;
	} else {
		*out_fs_uid = host_uid;
		ret = idsmap_noent_status(idsm);
	}
	return ret;
}

static int idsmap_resolve_uftoh(const struct silofs_idsmap *idsm,
                                uid_t fs_uid, uid_t *out_host_uid)
{
	const struct silofs_umap_entry *ume;
	int ret;

	ume = idsmap_lookup_uftoh(idsm, fs_uid);
	if (ume != NULL) {
		*out_host_uid = ume->um.host_uid;
		ret = 0;
	} else {
		*out_host_uid = fs_uid;
		ret = idsmap_noent_status(idsm);
	}
	return ret;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gmap_entry *
idsmap_new_gme(const struct silofs_idsmap *idsm, gid_t host_gid, gid_t fs_gid)
{
	return gme_new(idsm->idm_alloc, host_gid, fs_gid);
}

static void idsmap_del_gme(const struct silofs_idsmap *idsm,
                           struct silofs_gmap_entry *gme)
{
	gme_del(gme, idsm->idm_alloc);
}

static size_t
idsmap_gmap_slot_of(const struct silofs_idsmap *idsm, gid_t gid)
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

static int idsmap_insert_gmap(struct silofs_idsmap *idsm,
                              gid_t host_gid, gid_t fs_gid)
{
	struct silofs_gmap_entry *gme = NULL;
	struct silofs_list_head *lst = NULL;

	gme = idsmap_new_gme(idsm, host_gid, fs_gid);
	if (gme == NULL) {
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
		silofs_assert_gt(idsm->idm_gsize, 0);

		gme = gme_by_htof_lh(itr);
		if (gme->gm.host_gid == host_gid) {
			return gme;
		}
		itr = itr->next;
	}
	return NULL;
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
		silofs_assert_gt(idsm->idm_gsize, 0);

		gme = gme_by_ftoh_lh(itr);
		if (gme->gm.fs_gid == fs_gid) {
			return gme;
		}
		itr = itr->next;
	}
	return NULL;
}

static int idsmap_resolve_ghtof(const struct silofs_idsmap *idsm,
                                gid_t host_gid, gid_t *out_fs_gid)
{
	const struct silofs_gmap_entry *gme;
	int ret;

	gme = idsmap_lookup_ghtof(idsm, host_gid);
	if (gme != NULL) {
		*out_fs_gid = gme->gm.fs_gid;
		ret = 0;
	} else {
		*out_fs_gid = host_gid;
		ret = idsmap_noent_status(idsm);
	}
	return ret;
}

static int idsmap_resolve_gftoh(const struct silofs_idsmap *idsm,
                                gid_t fs_gid, gid_t *out_host_gid)
{
	const struct silofs_gmap_entry *gme;
	int ret;

	gme = idsmap_lookup_gftoh(idsm, fs_gid);
	if (gme != NULL) {
		*out_host_gid = gme->gm.host_gid;
		ret = 0;
	} else {
		*out_host_gid = fs_gid;
		ret = idsmap_noent_status(idsm);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int idsmap_add_id(struct silofs_idsmap *idsm,
                         const struct silofs_id *id)
{
	int ret = 0;

	if (idt_is_gid(id->id_type)) {
		ret = idsmap_insert_gmap(idsm, id->id.g.gid, id->id.g.sgid);
	} else if (idt_is_uid(id->id_type)) {
		ret = idsmap_insert_umap(idsm, id->id.u.uid, id->id.u.suid);
	}
	return ret;
}

int silofs_idsmap_populate(struct silofs_idsmap *idsm,
                           const struct silofs_ids *ids)
{
	int err = 0;

	if (ids == NULL) {
		return 0;
	}
	for (size_t i = 0; (i < ids->nuids) && !err; ++i) {
		err = idsmap_add_id(idsm, &ids->uids[i]);
	}
	for (size_t j = 0; (j < ids->ngids) && !err; ++j) {
		err = idsmap_add_id(idsm, &ids->gids[j]);
	}
	return err;
}

void silofs_idsmap_clear(struct silofs_idsmap *idsm)
{
	idsmap_clear_umap(idsm);
	idsmap_clear_gmap(idsm);
}

int silofs_idsmap_map_uidgid(const struct silofs_idsmap *idsm,
                             uid_t host_uid, gid_t host_gid,
                             uid_t *out_fs_uid, gid_t *out_fs_gid)
{
	int err1;
	int err2;

	if (host_uid != (uid_t)(-1)) {
		err1 = idsmap_resolve_uhtof(idsm, host_uid, out_fs_uid);
	} else {
		*out_fs_uid = host_uid;
		err1 = 0;
	}
	if (host_gid != (gid_t)(-1)) {
		err2 = idsmap_resolve_ghtof(idsm, host_gid, out_fs_gid);
	} else {
		*out_fs_gid = host_gid;
		err2 = 0;
	}
	return err1 ? err1 : err2;
}

int silofs_idsmap_map_creds(const struct silofs_idsmap *idsm,
                            struct silofs_creds *creds)
{
	const struct silofs_cred *xcred = &creds->xcred;
	struct silofs_cred *icred = &creds->icred;

	return silofs_idsmap_map_uidgid(idsm, xcred->uid, xcred->gid,
	                                &icred->uid, &icred->gid);
}

int silofs_idsmap_rmap_uidgid(const struct silofs_idsmap *idsm,
                              uid_t fs_uid, gid_t fs_gid,
                              uid_t *out_host_uid, gid_t *out_host_gid)
{
	int err1;
	int err2;

	if (fs_uid != (uid_t)(-1)) {
		err1 = idsmap_resolve_uftoh(idsm, fs_uid, out_host_uid);
	} else {
		*out_host_uid = fs_uid;
		err1 = 0;
	}
	if (fs_gid != (gid_t)(-1)) {
		err2 = idsmap_resolve_gftoh(idsm, fs_gid, out_host_gid);
	} else {
		*out_host_gid = fs_gid;
		err2 = 0;
	}
	return err1 ? err1 : err2;
}

int silofs_idsmap_rmap_stat(const struct silofs_idsmap *idsm,
                            struct silofs_stat *st)
{
	return silofs_idsmap_rmap_uidgid(idsm, st->st.st_uid, st->st.st_gid,
	                                 &st->st.st_uid, &st->st.st_gid);
}

int silofs_idsmap_rmap_statx(const struct silofs_idsmap *idsm,
                             struct statx *stx)
{
	return silofs_idsmap_rmap_uidgid(idsm, stx->stx_uid, stx->stx_gid,
	                                 &stx->stx_uid, &stx->stx_gid);
}
