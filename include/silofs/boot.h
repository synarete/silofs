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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_


/* boot pathname: a pair of repo-directory & boot-record name (optional) */
struct silofs_bootpath {
	struct silofs_str               repodir;
	struct silofs_namestr           name;
};

/* boot-record representation (in-memory) */
struct silofs_bootrec {
	struct silofs_uuid              uuid;
	struct silofs_ulink             sb_ulink;
	struct silofs_cipher_args       cip_args;
	struct silofs_hash256           key_hash;
	enum silofs_bootf               flags;
};

/* boot-records pair after fork-fs */
struct silofs_bootrecs {
	struct silofs_bootrec           brec[2];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec1k_init(struct silofs_bootrec1k *brec1k);

void silofs_bootrec1k_fini(struct silofs_bootrec1k *brec1k);

void silofs_bootrec1k_stamp(struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest *md);

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest *md);

void silofs_bootrec1k_parse(const struct silofs_bootrec1k *brec1k,
                            struct silofs_bootrec *brec);

void silofs_bootrec1k_set(struct silofs_bootrec1k *brec1k,
                          const struct silofs_bootrec *brec);

void silofs_bootrec1k_setn(struct silofs_bootrec1k *brec1k,
                           const struct silofs_bootrec *brec, size_t n);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec);

void silofs_bootrec_fini(struct silofs_bootrec *brec);

void silofs_bootrec_uuid(const struct silofs_bootrec *brec,
                         struct silofs_uuid *out_uuid);

void silofs_bootrec_set_uuid(struct silofs_bootrec *brec,
                             const struct silofs_uuid *uuid);

void silofs_bootrec_sb_ulink(const struct silofs_bootrec *brec,
                             struct silofs_ulink *out_ulink);

void silofs_bootrec_set_sb_ulink(struct silofs_bootrec *brec,
                                 const struct silofs_ulink *sb_ulink);

void silofs_bootrec_set_keyhash(struct silofs_bootrec *brec,
                                const struct silofs_hash256 *hash);

void silofs_bootrec_clear_keyhash(struct silofs_bootrec *brec);

int silofs_bootrec_check_keyhash(const struct silofs_bootrec *brec,
                                 const struct silofs_hash256 *hash);

void silofs_bootrec_cipher_args(const struct silofs_bootrec *brec,
                                struct silofs_cipher_args *out_cip_args);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp,
                          const char *repodir, const char *name);

void silofs_bootpath_assign(struct silofs_bootpath *bpath,
                            const struct silofs_bootpath *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_name(const struct silofs_namestr *nstr);

int silofs_make_namestr(struct silofs_namestr *nstr, const char *s);

int silofs_make_fsnamestr(struct silofs_namestr *nstr, const char *s);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_default_cip_args(struct silofs_cipher_args *cip_args);

void silofs_calc_key_hash(const struct silofs_key *key,
                          const struct silofs_mdigest *md,
                          struct silofs_hash256 *out_hash);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_init_lib(void);

void silofs_validate_fsdefs(void);

#endif /* SILOFS_BOOT_H_ */
