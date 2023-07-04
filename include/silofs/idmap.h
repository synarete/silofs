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
#ifndef SILOFS_IDMAP_H_
#define SILOFS_IDMAP_H_

enum silofs_idtype {
	SILOFS_IDTYPE_NONE      = 0,
	SILOFS_IDTYPE_UID       = 1,
	SILOFS_IDTYPE_GID       = 2,
};

/* mapping between host uid and internal */
struct silofs_uid_pair {
	uid_t uid;
	uid_t suid;
};

/* mapping between host gid and internal */
struct silofs_gid_pair {
	gid_t gid;
	gid_t sgid;
};

/* user-or-group id-mapping */
union silofs_id_u {
	struct silofs_uid_pair  u;
	struct silofs_gid_pair  g;
};

/* id-mapping */
struct silofs_id {
	union silofs_id_u       id;
	enum silofs_idtype      id_type;
};

/* user-id host-to-fs bidirectional-mapping */
struct silofs_uid_map {
	uid_t host_uid;
	uid_t fs_uid;
};

/* group-id host-to-fs bidirectional-mapping */
struct silofs_gid_map {
	gid_t host_gid;
	gid_t fs_gid;
};

/* bi-directional id-mapping hash-table (external-internal) */
struct silofs_idsmap {
	struct silofs_alloc     *idm_alloc;
	struct silofs_list_head *idm_uhtof;
	struct silofs_list_head *idm_uftoh;
	struct silofs_list_head *idm_ghtof;
	struct silofs_list_head *idm_gftoh;
	size_t  idm_uhcap;
	size_t idm_usize;
	size_t idm_ghcap;
	size_t idm_gsize;
	bool   idm_allow_hotids;

};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_idsmap_init(struct silofs_idsmap *idsm,
                       struct silofs_alloc *alloc, bool allow_hostids);

void silofs_idsmap_fini(struct silofs_idsmap *idsm);

void silofs_idsmap_clear(struct silofs_idsmap *idsm);

int silofs_idsmap_populate(struct silofs_idsmap *idsm,
                           const struct silofs_ids *ids);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_idsmap_map_uidgid(const struct silofs_idsmap *idsm,
                             uid_t host_uid, gid_t host_gid,
                             uid_t *out_fs_uid, gid_t *out_fs_gid);

int silofs_idsmap_rmap_uidgid(const struct silofs_idsmap *idsm,
                              uid_t fs_uid, gid_t fs_gid,
                              uid_t *out_fs_uid, gid_t *out_fs_gid);

int silofs_idsmap_map_creds(const struct silofs_idsmap *idsm,
                            struct silofs_creds *creds);

int silofs_idsmap_rmap_stat(const struct silofs_idsmap *idsm,
                            struct silofs_stat *st);

int silofs_idsmap_rmap_statx(const struct silofs_idsmap *idsm,
                             struct statx *stx);

#endif /* SILOFS_IDMAP_H_ */
