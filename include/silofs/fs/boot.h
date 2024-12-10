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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/ps.h>
#include <silofs/fs/types.h>
#include <silofs/fs/idsmap.h>

struct silofs_fsenv;

/* boot pathname: a pair of repo-directory & boot-record name (optional) */
struct silofs_bootpath {
	struct silofs_strview repodir;
	struct silofs_namestr name;
};

/* boot-record representation (in-memory) */
struct silofs_bootrec {
	struct silofs_uuid   uuid;
	struct silofs_ivkey  main_ivkey;
	struct silofs_ulink  sb_ulink;
	struct silofs_prange prange;
	enum silofs_bootf    flags;
	int32_t              cipher_algo;
	int32_t              cipher_mode;
};

/* boot-records pair after fork-fs with their content-addresses */
struct silofs_bootrecs {
	struct silofs_bootrec brec_new;
	struct silofs_bootrec brec_alt;
	struct silofs_caddr   caddr_new;
	struct silofs_caddr   caddr_alt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* file-system's control flags (as explicit booleans) */
struct silofs_fs_cflags {
	bool pedantic;
	bool rdonly;
	bool noexec;
	bool nosuid;
	bool nodev;
	bool with_fuse;
	bool asyncwr;
	bool allow_admin;
	bool allow_other;
	bool allow_hostids;
	bool allow_xattr_acl;
	bool writeback_cache;
	bool may_splice;
	bool lazytime;
	bool stdalloc;
};

/* file-system's boot reference */
struct silofs_fs_bref {
	struct silofs_caddr caddr;
	const char         *repodir;
	const char         *name;
	const char         *passwd;
};

/* file-system's arguments */
struct silofs_fs_args {
	struct silofs_fs_bref   bref;
	struct silofs_fs_ids    ids;
	struct silofs_fs_cflags cflags;
	const char             *mntdir;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootref_init(struct silofs_fs_bref *bref);

void silofs_bootref_fini(struct silofs_fs_bref *bref);

void silofs_bootref_assign(struct silofs_fs_bref       *bref,
                           const struct silofs_fs_bref *other);

void silofs_bootref_update(struct silofs_fs_bref     *bref,
                           const struct silofs_caddr *caddr, const char *name);

int silofs_bootref_import(struct silofs_fs_bref       *bref,
                          const struct silofs_strview *sv);

void silofs_bootref_export(const struct silofs_fs_bref *bref,
                           struct silofs_strbuf        *sbuf);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec1k_init(struct silofs_bootrec1k *brec1k);

void silofs_bootrec1k_fini(struct silofs_bootrec1k *brec1k);

void silofs_bootrec1k_stamp(struct silofs_bootrec1k     *brec1k,
                            const struct silofs_mdigest *md);

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest   *md);

void silofs_bootrec1k_xtoh(const struct silofs_bootrec1k *brec1k,
                           struct silofs_bootrec         *brec);

void silofs_bootrec1k_htox(struct silofs_bootrec1k     *brec1k,
                           const struct silofs_bootrec *brec);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec);

void silofs_bootrec_fini(struct silofs_bootrec *brec);

void silofs_bootrec_setup(struct silofs_bootrec *brec);

void silofs_bootrec_assign(struct silofs_bootrec       *brec,
                           const struct silofs_bootrec *other);

void silofs_bootrec_gen_uuid(struct silofs_bootrec *brec);

void silofs_bootrec_set_ivkey(struct silofs_bootrec     *brec,
                              const struct silofs_ivkey *ivkey);

void silofs_bootrec_gen_ivkey(struct silofs_bootrec *brec);

void silofs_bootrec_prange(const struct silofs_bootrec *brec,
                           struct silofs_prange        *out_prange);

void silofs_bootrec_set_prange(struct silofs_bootrec      *brec,
                               const struct silofs_prange *prange);

void silofs_bootrec_sb_ulink(const struct silofs_bootrec *brec,
                             struct silofs_ulink         *out_ulink);

void silofs_bootrec_set_sb_ulink(struct silofs_bootrec     *brec,
                                 const struct silofs_ulink *sb_ulink);

void silofs_bootrec_lvid(const struct silofs_bootrec *brec,
                         struct silofs_lvid          *out_lvid);

void silofs_bootrec_self_uaddr(const struct silofs_bootrec *brec,
                               struct silofs_uaddr         *out_uaddr);

void silofs_make_bootrec_uaddr(const struct silofs_lvid *lvid,
                               struct silofs_uaddr      *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp, const char *repodir,
                          const char *name);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_name(const struct silofs_namestr *nstr);

int silofs_make_namestr(struct silofs_namestr *nstr, const char *s);

int silofs_make_fsnamestr(struct silofs_namestr *nstr, const char *s);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_calc_key_hash(const struct silofs_key     *key,
                          const struct silofs_mdigest *md,
                          struct silofs_hash256       *out_hash);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encode_bootrec(const struct silofs_fsenv   *fsenv,
                          const struct silofs_bootrec *brec,
                          struct silofs_bootrec1k     *out_brec1k_enc);

int silofs_decode_bootrec(const struct silofs_fsenv     *fsenv,
                          const struct silofs_bootrec1k *brec1k_enc,
                          struct silofs_bootrec         *out_brec);

int silofs_save_bootrec(const struct silofs_fsenv   *fsenv,
                        const struct silofs_bootrec *brec,
                        struct silofs_caddr         *out_caddr);

int silofs_load_bootrec(const struct silofs_fsenv *fsenv,
                        const struct silofs_caddr *caddr,
                        struct silofs_bootrec     *out_brec);

int silofs_stat_bootrec(const struct silofs_fsenv *fsenv,
                        const struct silofs_caddr *caddr);

int silofs_unlink_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_caddr *caddr);

int silofs_calc_bootrec_caddr(const struct silofs_fsenv   *fsenv,
                              const struct silofs_bootrec *brec,
                              struct silofs_caddr         *out_caddr);

#endif /* SILOFS_BOOT_H_ */
