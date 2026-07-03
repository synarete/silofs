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
#ifndef SILOFS_ADDR_H_
#define SILOFS_ADDR_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <silofs/ondisk.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/crypt.h>

#include <silofs/addr/offlen.h>
#include <silofs/addr/htox.h>
#include <silofs/addr/uniqid.h>
#include <silofs/addr/blobid.h>
#include <silofs/addr/paddr.h>
#include <silofs/addr/laddr.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* hash */

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

void silofs_hash256_assign(struct silofs_hash256       *hash,
                           const struct silofs_hash256 *other);

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256       *other);

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf        *out_name);

int silofs_hash256_to_str(const struct silofs_hash256 *hash, char *str,
                          size_t len);

int silofs_hash256_from_str(struct silofs_hash256 *hash, const char *str,
                            size_t len);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* nmeta */

/* nodes meta settings */
struct silofs_nmeta {
	struct silofs_civkey civkey;
	struct silofs_ciargs ciargs;
	struct silofs_ctag   ctag;
};

const struct silofs_nmeta *silofs_nmeta_none(void);

void silofs_nmeta_setup(struct silofs_nmeta        *nmeta,
                        const struct silofs_civkey *civkey);

void silofs_nmeta_reset(struct silofs_nmeta *nmeta);

void silofs_nmeta_assign(struct silofs_nmeta       *nmeta,
                         const struct silofs_nmeta *other);

void silofs_nmeta_update(struct silofs_nmeta      *nmeta,
                         const struct silofs_ctag *ctag);

bool silofs_nmeta_isequal(const struct silofs_nmeta *nmeta,
                          const struct silofs_nmeta *other);

void silofs_nmeta128b_htox(struct silofs_nmeta128b   *nmeta128,
                           const struct silofs_nmeta *nmeta);

void silofs_nmeta128b_xtoh(const struct silofs_nmeta128b *nmeta128,
                           struct silofs_nmeta           *nmeta);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pnptr */

/* pnode meta pointer */
struct silofs_pnptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
};

const struct silofs_pnptr *silofs_pnptr_none(void);

void silofs_pnptr_setup(struct silofs_pnptr        *pnptr,
                        const struct silofs_paddr  *paddr,
                        const struct silofs_civkey *civkey);

void silofs_pnptr_setup2(struct silofs_pnptr       *pnptr,
                         const struct silofs_paddr *paddr,
                         const struct silofs_nmeta *nmeta);

void silofs_pnptr_reset(struct silofs_pnptr *pnptr);

void silofs_pnptr_assign(struct silofs_pnptr       *pnptr,
                         const struct silofs_pnptr *other);

bool silofs_pnptr_isequal(const struct silofs_pnptr *pnptr,
                          const struct silofs_pnptr *other);

bool silofs_pnptr_isnull(const struct silofs_pnptr *pnptr);

void silofs_pnptr256b_htox(struct silofs_pnptr256b   *pnptr256,
                           const struct silofs_pnptr *pnptr);

void silofs_pnptr256b_xtoh(const struct silofs_pnptr256b *pnptr256,
                           struct silofs_pnptr           *pnptr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spdesc */

/* space descriptor as p-addresses range */
struct silofs_spdesc {
	struct silofs_paddr beg;
	struct silofs_paddr end;
};

const struct silofs_spdesc *silofs_spdesc_none(void);

void silofs_spdesc_setup(struct silofs_spdesc      *spdesc,
                         const struct silofs_paddr *beg,
                         const struct silofs_paddr *end);

void silofs_spdesc_setup1(struct silofs_spdesc      *spdesc,
                          const struct silofs_paddr *beg);

void silofs_spdesc_htox(struct silofs_spdesc128b   *spdesc128,
                        const struct silofs_spdesc *spdesc);

void silofs_spdesc_xtoh(const struct silofs_spdesc128b *spdesc128,
                        struct silofs_spdesc           *spdesc);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* genid */

void silofs_generate_civ(struct silofs_prandgen *prng,
                         struct silofs_civ      *out_civ);

void silofs_generate_ckey(struct silofs_prandgen *prng,
                          struct silofs_ckey     *out_ckey);

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid   *out_uniqid);

void silofs_generate_layerid(struct silofs_layerid *out_layerid);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* mbref */

/* MBR reference address */
struct silofs_mbref {
	struct silofs_blobidx bx;
};

/* mbr-refs tuple */
struct silofs_mbrefs {
	struct silofs_mbref main;
	struct silofs_mbref base;
	struct silofs_mbref fork;
};

void silofs_mbref_reset(struct silofs_mbref *mbref);

void silofs_mbref_setup(struct silofs_mbref         *mbref,
                        const struct silofs_blobidx *blobidx);

void silofs_mbref_assign(struct silofs_mbref       *mbref,
                         const struct silofs_mbref *other);

void silofs_mbref_derive(struct silofs_mbref            *mbref,
                         const struct silofs_mdigest_hd *md_hd,
                         const struct silofs_paddr      *paddr);

bool silofs_mbref_isequal(const struct silofs_mbref *mbref,
                          const struct silofs_mbref *other);

int silofs_mbref_from_str(struct silofs_mbref *mbref, const char *str,
                          size_t len);

int silofs_mbref_to_str(const struct silofs_mbref *mbref, char *str, size_t n);

void silofs_mbrefs_assign(struct silofs_mbrefs       *mbrefs,
                          const struct silofs_mbrefs *other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* fsref */

void silofs_fsmeta_setup(struct silofs_fsmeta *fsmeta);

void silofs_fsref_export(struct silofs_fsref       *fsref,
                         const struct silofs_mbref *mbref);

int silofs_fsref_import(const struct silofs_fsref *fsref,
                        struct silofs_mbref       *out_mbref);

void silofs_fsrefs_export(struct silofs_fsrefs       *fsrefs,
                          const struct silofs_mbrefs *mbrefs);

#include <silofs/addr/creds.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* namestr */

/* name-string: a pair of string-view and (optional) 64-bits hash */
struct silofs_namestr {
	struct silofs_strview sv;
	uint64_t              hash;
};

int silofs_namestr_init(struct silofs_namestr *nstr, const char *s);

int silofs_namestr_init_by(struct silofs_namestr       *nstr,
                           const struct silofs_strview *sv);

int silofs_namestr_calc_hash(struct silofs_namestr          *nstr,
                             const struct silofs_mdigest_hd *md,
                             enum silofs_namehfn nhfn, uint64_t seed);

int silofs_check_fsname(const struct silofs_namestr *nstr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#endif /* SILOFS_ADDR_H_ */
