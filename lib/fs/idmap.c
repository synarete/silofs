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
#include <silofs/fs.h>
#include <silofs/fs-private.h>


/* in-memory host<-->silo uid/gid mapping entry */
struct silofs_id_entry {
	struct silofs_list_head id_lh;
	struct silofs_id        id;
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

static struct silofs_id_entry *
ide_by_lh(const struct silofs_list_head *lh)
{
	const struct silofs_id_entry *ide;

	ide = container_of2(lh, struct silofs_id_entry, id_lh);
	return unconst(ide);
}

static void
ide_init_by_uid(struct silofs_id_entry *ide, uid_t uid, uid_t suid)
{
	list_head_init(&ide->id_lh);
	ide->id.id.u.uid = uid;
	ide->id.id.u.suid = suid;
	ide->id.id_type = SILOFS_IDTYPE_UID;
}

static void
ide_init_by_gid(struct silofs_id_entry *ide, gid_t gid, gid_t sgid)
{
	list_head_init(&ide->id_lh);
	ide->id.id.g.gid = gid;
	ide->id.id.g.sgid = sgid;
	ide->id.id_type = SILOFS_IDTYPE_GID;
}

static void ide_fini(struct silofs_id_entry *ide)
{
	list_head_fini(&ide->id_lh);
	ide->id.id_type = SILOFS_IDTYPE_NONE;
}

static bool ide_has_uid(const struct silofs_id_entry *ide, uid_t uid)
{
	return idt_is_uid(ide->id.id_type) && uid_eq(ide->id.id.u.uid, uid);
}

static bool ide_has_suid(const struct silofs_id_entry *ide, uid_t suid)
{
	return idt_is_uid(ide->id.id_type) && uid_eq(ide->id.id.u.suid, suid);
}

static bool ide_has_gid(const struct silofs_id_entry *ide, gid_t gid)
{
	return idt_is_gid(ide->id.id_type) && gid_eq(ide->id.id.g.gid, gid);
}

static bool ide_has_sgid(const struct silofs_id_entry *ide, gid_t sgid)
{
	return idt_is_gid(ide->id.id_type) && gid_eq(ide->id.id.g.sgid, sgid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_idsmap_init(struct silofs_idsmap *idsm,
                       struct silofs_alloc *alloc, bool allow_hostids)
{
	list_head_initn(idsm->idm_xtoi, ARRAY_SIZE(idsm->idm_xtoi));
	list_head_initn(idsm->idm_itox, ARRAY_SIZE(idsm->idm_itox));
	idsm->idm_alloc = alloc;
	idsm->idm_size = 0;
	idsm->idm_allow_hotids = allow_hostids;
	return 0;
}

void silofs_idsmap_fini(struct silofs_idsmap *idsm)
{
	silofs_idsmap_clear(idsm);
	list_head_finin(idsm->idm_xtoi, ARRAY_SIZE(idsm->idm_xtoi));
	list_head_finin(idsm->idm_itox, ARRAY_SIZE(idsm->idm_itox));
	idsm->idm_alloc = NULL;
}

static size_t
idsmap_id_to_slot(const struct silofs_idsmap *idsm, uint32_t id)
{
	STATICASSERT_EQ(ARRAY_SIZE(idsm->idm_xtoi),
	                ARRAY_SIZE(idsm->idm_itox));

	return id % ARRAY_SIZE(idsm->idm_xtoi);
}

static struct silofs_list_head *
idsmap_xtoi_bin_by_id(const struct silofs_idsmap *idsm, uint32_t id)
{
	const size_t slot = idsmap_id_to_slot(idsm, id);
	const struct silofs_list_head *lst = &idsm->idm_xtoi[slot];

	return unconst(lst);
}

static struct silofs_list_head *
idsmap_itox_bin_by_id(const struct silofs_idsmap *idsm, uint32_t id)
{
	const size_t slot = idsmap_id_to_slot(idsm, id);
	const struct silofs_list_head *lst = &idsm->idm_itox[slot];

	return unconst(lst);
}

static int idsmap_default_status(const struct silofs_idsmap *idsm)
{
	return idsm->idm_allow_hotids ? 0 : -ENOENT;
}

static int idsmap_xtoi_uid(const struct silofs_idsmap *idsm,
                           uid_t uid, uid_t *out_suid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_id_entry *ide = NULL;

	*out_suid = uid;
	lst = idsmap_xtoi_bin_by_id(idsm, uid);
	for (itr = lst->next; itr != lst; itr = itr->next) {
		ide = ide_by_lh(itr);
		if (ide_has_uid(ide, uid)) {
			*out_suid = ide->id.id.u.suid;
			return 0;
		}
	}
	return idsmap_default_status(idsm);
}

static int idsmap_itox_uid(const struct silofs_idsmap *idsm,
                           uid_t suid, uid_t *out_uid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_id_entry *ide = NULL;

	*out_uid = suid;
	lst = idsmap_itox_bin_by_id(idsm, suid);
	for (itr = lst->next; itr != lst; itr = itr->next) {
		ide = ide_by_lh(itr);
		if (ide_has_suid(ide, suid)) {
			*out_uid = ide->id.id.u.uid;
			return 0;
		}
	}
	return idsmap_default_status(idsm);
}

static int idsmap_xtoi_gid(const struct silofs_idsmap *idsm,
                           gid_t gid, uid_t *out_sgid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_id_entry *ide = NULL;

	*out_sgid = gid;
	lst = idsmap_xtoi_bin_by_id(idsm, gid);
	for (itr = lst->next; itr != lst; itr = itr->next) {
		ide = ide_by_lh(itr);
		if (ide_has_gid(ide, gid)) {
			*out_sgid = ide->id.id.g.sgid;
			return 0;
		}
	}
	return idsmap_default_status(idsm);
}

static int idsmap_itox_gid(const struct silofs_idsmap *idsm,
                           gid_t sgid, uid_t *out_gid)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_id_entry *ide = NULL;

	*out_gid = sgid;
	lst = idsmap_itox_bin_by_id(idsm, sgid);
	for (itr = lst->next; itr != lst; itr = itr->next) {
		ide = ide_by_lh(itr);
		if (ide_has_sgid(ide, sgid)) {
			*out_gid = ide->id.id.g.gid;
			return 0;
		}
	}
	return idsmap_default_status(idsm);
}

static struct silofs_id_entry *
idsmap_new_id_mapping_by_uid(const struct silofs_idsmap *idsm,
                             uid_t uid_host, uid_t suid)
{
	struct silofs_id_entry *ide;

	ide = silofs_allocate(idsm->idm_alloc, sizeof(*ide));
	if (ide != NULL) {
		ide_init_by_uid(ide, uid_host, suid);
	}
	return ide;
}

static int idsmap_add_uid(struct silofs_idsmap *idsm, uid_t uid, uid_t suid)
{
	struct silofs_list_head *lst;
	struct silofs_id_entry *ide;

	ide = idsmap_new_id_mapping_by_uid(idsm, uid, suid);
	if (ide == NULL) {
		return -ENOMEM;
	}
	lst = idsmap_xtoi_bin_by_id(idsm, uid);
	list_head_insert_after(lst, &ide->id_lh);
	idsm->idm_size++;

	ide = idsmap_new_id_mapping_by_uid(idsm, uid, suid);
	if (ide == NULL) {
		return -ENOMEM;
	}
	lst = idsmap_itox_bin_by_id(idsm, suid);
	list_head_insert_after(lst, &ide->id_lh);
	idsm->idm_size++;

	return 0;
}

static struct silofs_id_entry *
idsmap_new_id_mapping_by_gid(struct silofs_idsmap *idsm,
                             gid_t gid, gid_t sgid)
{
	struct silofs_id_entry *ide;

	ide = silofs_allocate(idsm->idm_alloc, sizeof(*ide));
	if (ide != NULL) {
		ide_init_by_gid(ide, gid, sgid);
	}
	return ide;
}

static int idsmap_add_gid(struct silofs_idsmap *idsm, gid_t gid, gid_t sgid)
{
	struct silofs_list_head *lst = NULL;
	struct silofs_id_entry *ide;

	ide = idsmap_new_id_mapping_by_gid(idsm, gid, sgid);
	if (ide == NULL) {
		return -ENOMEM;
	}
	lst = idsmap_xtoi_bin_by_id(idsm, gid);
	list_head_insert_after(lst, &ide->id_lh);
	idsm->idm_size++;

	ide = idsmap_new_id_mapping_by_gid(idsm, gid, sgid);
	if (ide == NULL) {
		return -ENOMEM;
	}
	lst = idsmap_itox_bin_by_id(idsm, sgid);
	list_head_insert_after(lst, &ide->id_lh);
	idsm->idm_size++;

	return 0;
}

static int idsmap_add_id(struct silofs_idsmap *idsm,
                         const struct silofs_id *id)
{
	int err;

	if (idt_is_uid(id->id_type)) {
		err = idsmap_add_uid(idsm, id->id.u.uid, id->id.u.suid);
	} else if (idt_is_gid(id->id_type)) {
		err = idsmap_add_gid(idsm, id->id.g.gid, id->id.g.sgid);
	} else {
		err = 0;
	}
	return err;
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

static void idsmap_del_id_mapping(const struct silofs_idsmap *idsm,
                                  struct silofs_id_entry *ide)
{
	ide_fini(ide);
	silofs_deallocate(idsm->idm_alloc, ide, sizeof(*ide));
}

static void idsmap_clear_at(struct silofs_idsmap *idsm,
                            struct silofs_list_head *lst)
{
	struct silofs_list_head *itr;
	struct silofs_id_entry *ide = NULL;

	itr = lst->next;
	while (itr != lst) {
		ide = ide_by_lh(itr);
		itr = itr->next;

		list_head_remove(&ide->id_lh);
		idsmap_del_id_mapping(idsm, ide);
		idsm->idm_size--;
	}
}

void silofs_idsmap_clear(struct silofs_idsmap *idsm)
{
	for (size_t i = 0; i < ARRAY_SIZE(idsm->idm_xtoi); ++i) {
		idsmap_clear_at(idsm, &idsm->idm_xtoi[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(idsm->idm_itox); ++i) {
		idsmap_clear_at(idsm, &idsm->idm_itox[i]);
	}
}

int silofs_idsmap_map_uidgid(const struct silofs_idsmap *idsm,
                             uid_t uid, gid_t gid,
                             uid_t *out_suid, gid_t *out_sgid)
{
	int err1;
	int err2;

	if (uid != (uid_t)(-1)) {
		err1 = idsmap_xtoi_uid(idsm, uid, out_suid);
	} else {
		*out_suid = uid;
		err1 = 0;
	}
	if (gid != (gid_t)(-1)) {
		err2 = idsmap_xtoi_gid(idsm, gid, out_sgid);
	} else {
		*out_sgid = gid;
		err2 = 0;
	}
	return err1 ? err1 : err2;
}

int silofs_idsmap_map_creds(const struct silofs_idsmap *idsm,
                            struct silofs_creds *creds)
{
	const struct silofs_ucred *xcred = &creds->xcred;
	struct silofs_ucred *icred = &creds->icred;

	return silofs_idsmap_map_uidgid(idsm, xcred->uid, xcred->gid,
	                                &icred->uid, &icred->gid);
}

int silofs_idsmap_rmap_uidgid(const struct silofs_idsmap *idsm,
                              uid_t suid, gid_t sgid,
                              uid_t *out_uid, gid_t *out_gid)
{
	int err1;
	int err2;

	if (suid != (uid_t)(-1)) {
		err1 = idsmap_itox_uid(idsm, suid, out_uid);
	} else {
		*out_uid = suid;
		err1 = 0;
	}
	if (sgid != (gid_t)(-1)) {
		err2 = idsmap_itox_gid(idsm, sgid, out_gid);
	} else {
		*out_gid = sgid;
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
