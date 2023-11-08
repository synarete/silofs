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
	struct silofs_substr            repodir;
	struct silofs_namestr           name;
};

/* boot-record representation (in-memory) */
struct silofs_bootrec {
	struct silofs_ulink             sb_ulink;
	struct silofs_cipher_args       cip_args;
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

void silofs_bootrec1k_xtoh(const struct silofs_bootrec1k *brec1k,
                           struct silofs_bootrec *brec);

void silofs_bootrec1k_htox(struct silofs_bootrec1k *brec1k,
                           const struct silofs_bootrec *brec);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec);

void silofs_bootrec_fini(struct silofs_bootrec *brec);

void silofs_bootrec_sb_ulink(const struct silofs_bootrec *brec,
                             struct silofs_ulink *out_ulink);

void silofs_bootrec_set_sb_ulink(struct silofs_bootrec *brec,
                                 const struct silofs_ulink *sb_ulink);

void silofs_bootrec_cipher_args(const struct silofs_bootrec *brec,
                                struct silofs_cipher_args *out_cip_args);

void silofs_bootrec_pvid(const struct silofs_bootrec *brec,
                         struct silofs_pvid *out_pvid);

void silofs_bootrec_self_uaddr(const struct silofs_bootrec *brec,
                               struct silofs_uaddr *out_uaddr);

void silofs_make_bootrec_uaddr(const struct silofs_pvid *pvid,
                               struct silofs_uaddr *out_uaddr);


void silofs_bootrecs_to_pvids(const struct silofs_bootrecs *brecs,
                              struct silofs_pvid *out_pvid_new,
                              struct silofs_pvid *out_pvid_alt);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootrec_encode(const struct silofs_bootrec *brec,
                          struct silofs_bootrec1k *brec1k,
                          const struct silofs_crypto *crypto,
                          const struct silofs_ivkey *ivkey);

int silofs_bootrec_decode(struct silofs_bootrec *brec,
                          struct silofs_bootrec1k *brec1k,
                          const struct silofs_crypto *crypto,
                          const struct silofs_ivkey *ivkey);

int silofs_ivkey_for_bootrec(struct silofs_ivkey *ivkey,
                             const struct silofs_password *passwd,
                             const struct silofs_mdigest *mdigest);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp,
                          const char *repodir, const char *name);

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
