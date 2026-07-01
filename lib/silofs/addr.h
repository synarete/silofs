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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* stype */

struct silofs_stype {
	enum silofs_ptype ptype;
	enum silofs_ltype ltype;
};

size_t silofs_ptype_size(enum silofs_ptype ptype);

bool silofs_ltype_isnone(enum silofs_ltype ltype);

bool silofs_ltype_isinode(enum silofs_ltype ltype);

bool silofs_ltype_islnode(enum silofs_ltype ltype);

bool silofs_ltype_isdata(enum silofs_ltype ltype);

bool silofs_ltype_usespmap(enum silofs_ltype ltype);

size_t silofs_ltype_size(enum silofs_ltype ltype);

ssize_t silofs_ltype_ssize(enum silofs_ltype ltype);

size_t silofs_ltype_nkbs(enum silofs_ltype ltype);

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
/* layerid */
const struct silofs_layerid *silofs_layerid_none(void);

void silofs_layerid_reset(struct silofs_layerid *layerid);

void silofs_layerid_assign(struct silofs_layerid       *layerid,
                           const struct silofs_layerid *other);

void silofs_layerid_assignx(struct silofs_layerid       *layerid,
                            const struct silofs_layerid *other);

long silofs_layerid_compare(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other);

bool silofs_layerid_isequal(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uniqid_reset(struct silofs_uniqid *uniqid);

void silofs_uniqid_setup_by(struct silofs_uniqid        *uniqid,
                            const struct silofs_hash256 *hash);

void silofs_uniqid_assign(struct silofs_uniqid       *uniqid,
                          const struct silofs_uniqid *other);

void silofs_uniqid_assignx(struct silofs_uniqid       *uniqid,
                           const struct silofs_uniqid *other);

long silofs_uniqid_compare(const struct silofs_uniqid *uniqid,
                           const struct silofs_uniqid *other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* blobid */
struct silofs_blobid {
	struct silofs_layerid layerid;
	struct silofs_uniqid  uniqid;
	struct silofs_stype   stype;
	uint16_t              vers;
};

const struct silofs_blobid *silofs_blobid_none(void);

void silofs_blobid_init(struct silofs_blobid        *blobid,
                        const struct silofs_stype   *stype,
                        const struct silofs_layerid *layerid,
                        const struct silofs_uniqid  *uniqid);

void silofs_blobid_fini(struct silofs_blobid *blobid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_assign(struct silofs_blobid       *blobid,
                          const struct silofs_blobid *other);

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

size_t silofs_blobid_slotsize(const struct silofs_blobid *blobid);

void silofs_blobid56b_htox(struct silofs_blobid56b    *blobid56,
                           const struct silofs_blobid *blobid);

void silofs_blobid56b_xtoh(const struct silofs_blobid56b *blobid56,
                           struct silofs_blobid          *blobid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobidx_setup(struct silofs_blobidx       *blobidx,
                          const struct silofs_hash256 *h);

void silofs_blobidx_assign(struct silofs_blobidx       *blobidx,
                           const struct silofs_blobidx *other);

void silofs_blobidx_derive(struct silofs_blobidx          *blobidx,
                           const struct silofs_mdigest_hd *md_hd,
                           const struct silofs_blobid     *blobid);

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other);

int silofs_blobidx_to_str(const struct silofs_blobidx *blobidx, char *str,
                          size_t len);

int silofs_blobidx_from_str(struct silofs_blobidx *blobidx, const char *str,
                            size_t len);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* paddr */

#include <silofs/addr/paddr.h>

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
/* laddr */
#include <silofs/addr/laddr.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* genid */

void silofs_generate_civ(struct silofs_prandgen *prng,
                         struct silofs_civ      *out_civ);

void silofs_generate_ckey(struct silofs_prandgen *prng,
                          struct silofs_ckey     *out_ckey);

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid   *out_uniqid);

void silofs_generate_layerid(struct silofs_prandgen *prng,
                             struct silofs_layerid  *out_layerid);

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

#include <silofs/addr/uidgid.h>

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
