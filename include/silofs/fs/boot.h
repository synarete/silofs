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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_


/* boot pathname: a pair of repo-directory & bootsec name (optional) */
struct silofs_bootpath {
	struct silofs_str       repodir;
	struct silofs_namestr   name;
};

/* boot-sector in-memory representation */
struct silofs_bootsec {
	struct silofs_hash256           key_hash;
	struct silofs_uuid              uuid;
	struct silofs_uaddr             sb_uaddr;
	struct silofs_packid            sb_packid;
	struct silofs_cipher_args       cip_args;
	enum silofs_bootf               flags;
};

/* boot-sector pair after fork-fs */
struct silofs_bootsecs {
	struct silofs_bootsec   bsec[2];
};

/* pair of boot-path and its referenced sec */
struct silofs_bootlink {
	struct silofs_bootpath  bpath;
	struct silofs_bootsec   bsec;
};

/* repository boot-loader*/
struct silofs_bootldr {
	struct silofs_mdigest   btl_md;
	int                     btl_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bsec1k_init(struct silofs_bootsec1k *bsc);

void silofs_bsec1k_fini(struct silofs_bootsec1k *bsc);

void silofs_bsec1k_stamp(struct silofs_bootsec1k *bsc,
                         const struct silofs_mdigest *md);

int silofs_bsec1k_verify(const struct silofs_bootsec1k *bsc,
                         const struct silofs_mdigest *md);

void silofs_bsec1k_parse(const struct silofs_bootsec1k *bsc,
                         struct silofs_bootsec *bsec);

void silofs_bsec1k_set(struct silofs_bootsec1k *bsc,
                       const struct silofs_bootsec *bsec);

void silofs_bsec1k_setn(struct silofs_bootsec1k *bsc,
                        const struct silofs_bootsec *bsec, size_t n);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootsec_init(struct silofs_bootsec *bsec);

void silofs_bootsec_fini(struct silofs_bootsec *bsec);

void silofs_bootsec_set_uaddr(struct silofs_bootsec *bsec,
                              const struct silofs_uaddr *sb_uaddr);

void silofs_bootsec_set_packid(struct silofs_bootsec *bsec,
                               const struct silofs_packid *sb_packid);

void silofs_bootsec_set_keyhash(struct silofs_bootsec *bsec,
                                const struct silofs_hash256 *hash);

void silofs_bootsec_clear_keyhash(struct silofs_bootsec *bsec);

bool silofs_bootsec_has_keyhash(const struct silofs_bootsec *bsec,
                                const struct silofs_hash256 *hash);

void silofs_bootsec_cipher_args(const struct silofs_bootsec *bsec,
                                struct silofs_cipher_args *out_cip_args);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp,
                          const char *repodir, const char *name);

void silofs_bootpath_assign(struct silofs_bootpath *bpath,
                            const struct silofs_bootpath *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootldr_init(struct silofs_bootldr *bldr);

void silofs_bootldr_fini(struct silofs_bootldr *bldr);

int silofs_bootldr_open(struct silofs_bootldr *bldr,
                        const struct silofs_bootpath *bpath);

int silofs_bootldr_close(struct silofs_bootldr *bldr);

int silofs_bootldr_fetch(const struct silofs_bootldr *bldr,
                         const struct silofs_bootpath *bpath,
                         struct silofs_bootsec *out_bsec);

int silofs_bootldr_store(const struct silofs_bootldr *bldr,
                         const struct silofs_bootpath *bpath,
                         const struct silofs_bootsec *bsec);

int silofs_bootldr_unref(const struct silofs_bootldr *bldr,
                         const struct silofs_bootpath *bpath);

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

int silofs_lib_setup(void);

void silofs_lib_verify_defs(void);

#endif /* SILOFS_BOOT_H_ */
