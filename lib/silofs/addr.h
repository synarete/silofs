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
#include <silofs/base.h>
#include <silofs/str.h>
#include <silofs/crypt.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* offlba */

typedef off_t silofs_lba_t;

bool silofs_off_isnull(off_t off);

off_t silofs_off_min(off_t off1, off_t off2);

off_t silofs_off_max(off_t off1, off_t off2);

off_t silofs_off_end(off_t off, size_t len);

off_t silofs_off_align(off_t off, ssize_t align);

off_t silofs_off_align_to_lbk(off_t off);

off_t silofs_off_next(off_t off, ssize_t len);

ssize_t silofs_off_diff(off_t beg, off_t end);

ssize_t silofs_off_len(off_t beg, off_t end);

size_t silofs_off_ulen(off_t beg, off_t end);

silofs_lba_t silofs_off_to_lba(off_t off);

off_t silofs_off_in_lbk(off_t off);

off_t silofs_off_next_lbk(off_t off);

off_t silofs_off_remainder(off_t off, size_t len);

bool silofs_lba_isnull(silofs_lba_t lba);

off_t silofs_lba_to_off(silofs_lba_t lba);

int silofs_verify_off(off_t off);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* htox */
uint64_t silofs_u8b_as_u64(const uint8_t p[8]);

void silofs_u8b_from_u64(uint8_t p[8], uint64_t u);

uint16_t silofs_cpu_to_le16(uint16_t n);

uint16_t silofs_le16_to_cpu(uint16_t n);

uint32_t silofs_cpu_to_le32(uint32_t n);

uint32_t silofs_le32_to_cpu(uint32_t n);

uint64_t silofs_cpu_to_le64(uint64_t n);

uint64_t silofs_le64_to_cpu(uint64_t n);

uint64_t silofs_cpu_to_ino(ino_t ino);

ino_t silofs_ino_to_cpu(uint64_t ino);

int64_t silofs_cpu_to_off(off_t off);

off_t silofs_off_to_cpu(int64_t off);

uint64_t silofs_cpu_to_time(time_t tm);

time_t silofs_time_to_cpu(uint64_t tm);

void silofs_ts_to_cpu(const struct silofs_timespec *t, struct timespec *ts);

void silofs_cpu_to_ts(const struct timespec *ts, struct silofs_timespec *t);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* stype */

struct silofs_stype {
	enum silofs_ptype ptype;
	enum silofs_vtype vtype;
};

size_t silofs_ptype_size(enum silofs_ptype ptype);

bool silofs_vtype_isnone(enum silofs_vtype vtype);

bool silofs_vtype_issuper(enum silofs_vtype vtype);

bool silofs_vtype_isspnode(enum silofs_vtype vtype);

bool silofs_vtype_isspleaf(enum silofs_vtype vtype);

bool silofs_vtype_isinode(enum silofs_vtype vtype);

bool silofs_vtype_isunode(enum silofs_vtype vtype);

bool silofs_vtype_isvnode(enum silofs_vtype vtype);

bool silofs_vtype_isdata(enum silofs_vtype vtype);

bool silofs_vtype_usespmap(enum silofs_vtype vtype);

size_t silofs_vtype_size(enum silofs_vtype vtype);

ssize_t silofs_vtype_ssize(enum silofs_vtype vtype);

size_t silofs_vtype_nkbs(enum silofs_vtype vtype);

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
	enum silofs_height    height;
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

/* persistent address with blob */
struct silofs_paddr {
	struct silofs_blobid blobid;
	off_t                pos;
	enum silofs_ptype    ptype;
};

const struct silofs_paddr *silofs_paddr_none(void);

void silofs_paddr_init(struct silofs_paddr        *paddr,
                       const struct silofs_blobid *blobid, off_t pos);

void silofs_paddr_fini(struct silofs_paddr *paddr);

void silofs_paddr_reset(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr       *paddr,
                         const struct silofs_paddr *other);

bool silofs_paddr_isequal(const struct silofs_paddr *paddr,
                          const struct silofs_paddr *other);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

void silofs_paddr_next(const struct silofs_paddr *paddr,
                       struct silofs_paddr       *out_next);

void silofs_paddr64b_htox(struct silofs_paddr64b    *paddr64,
                          const struct silofs_paddr *paddr);

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr          *paddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_calc_aad_by_paddr(const struct silofs_mdigest_hd *md_hd,
                              const struct silofs_paddr      *paddr,
                              struct silofs_caad             *out_caad);

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

/* logical-segment id within specific volume mapping */
struct silofs_lsid {
	struct silofs_blobid blobid;
	size_t               lsize;
	uint32_t             vindex;
};

/* logical-address within specific volume's mapping extend */
struct silofs_laddr {
	struct silofs_lsid lsid;
	off_t              pos;
};

/* logical-address and its associate IV-key */
struct silofs_llink {
	struct silofs_laddr  laddr;
	struct silofs_civkey civkey;
};

/* logical-space address-range [beg, end) */
struct silofs_lrange {
	off_t              beg;
	off_t              end;
	enum silofs_height height;
};

const struct silofs_lsid *silofs_lsid_none(void);

size_t silofs_lsid_size(const struct silofs_lsid *lsid);

bool silofs_lsid_isnull(const struct silofs_lsid *lsid);

bool silofs_lsid_has_blobid(const struct silofs_lsid   *lsid,
                            const struct silofs_blobid *blobid);

bool silofs_lsid_has_layerid(const struct silofs_lsid    *lsid,
                             const struct silofs_layerid *layerid);

void silofs_lsid_reset(struct silofs_lsid *lsid);

void silofs_lsid_setup(struct silofs_lsid         *lsid,
                       const struct silofs_blobid *blobid, off_t off);

void silofs_lsid_assign(struct silofs_lsid       *lsid,
                        const struct silofs_lsid *other);

bool silofs_lsid_isequal(const struct silofs_lsid *lsid,
                         const struct silofs_lsid *other);

uint64_t silofs_lsid_hash64(const struct silofs_lsid *lsid);

off_t silofs_lsid_pos(const struct silofs_lsid *lsid, off_t off);

void silofs_lsid64b_reset(struct silofs_lsid64b *lsid64);

void silofs_lsid64b_htox(struct silofs_lsid64b    *lsid64,
                         const struct silofs_lsid *lsid);

void silofs_lsid64b_xtoh(const struct silofs_lsid64b *lsid64,
                         struct silofs_lsid          *lsid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *silofs_laddr_none(void);

void silofs_laddr_setpos(struct silofs_laddr *laddr, off_t off);

void silofs_laddr_setup(struct silofs_laddr      *laddr,
                        const struct silofs_lsid *lsid, off_t off);

void silofs_laddr_setup_lbk(struct silofs_laddr      *laddr,
                            const struct silofs_lsid *lsid, off_t off);

void silofs_laddr_reset(struct silofs_laddr *laddr);

void silofs_laddr_assign(struct silofs_laddr       *laddr,
                         const struct silofs_laddr *other);

enum silofs_vtype silofs_laddr_vtype(const struct silofs_laddr *laddr);

size_t silofs_laddr_len(const struct silofs_laddr *laddr);

off_t silofs_laddr_end(const struct silofs_laddr *laddr);

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2);

bool silofs_laddr_isnull(const struct silofs_laddr *laddr);

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr);

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other);

void silofs_laddr96b_htox(struct silofs_laddr96b    *laddr96,
                          const struct silofs_laddr *laddr);

void silofs_laddr96b_xtoh(const struct silofs_laddr96b *laddr96,
                          struct silofs_laddr          *laddr);

void silofs_laddr96b_reset(struct silofs_laddr96b *laddr96);

void silofs_derive_iv_by_laddr(const struct silofs_mdigest_hd *md,
                               const struct silofs_laddr      *laddr,
                               struct silofs_civ              *out_iv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink       *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_ckey  *key,
                        const struct silofs_civ   *iv);

void silofs_llink_assign(struct silofs_llink       *llink,
                         const struct silofs_llink *other);

void silofs_llink_reset(struct silofs_llink *llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_lrange_isvalid(const struct silofs_lrange *lrange);

size_t silofs_lrange_len(const struct silofs_lrange *lrange);

bool silofs_lrange_within(const struct silofs_lrange *lrange, off_t off);

void silofs_lrange_setup(struct silofs_lrange *lrange,
                         enum silofs_height height, off_t beg, off_t end);

void silofs_lrange_setup_sub(struct silofs_lrange       *lrange,
                             const struct silofs_lrange *other, off_t beg);

void silofs_lrange_of_space(struct silofs_lrange *lrange,
                            enum silofs_height height, off_t voff_base);

void silofs_lrange_of_spmap(struct silofs_lrange *lrange,
                            enum silofs_height height, off_t voff_base);

off_t silofs_lrange_voff_at(const struct silofs_lrange *lrange, size_t slot);

off_t silofs_lrange_next(const struct silofs_lrange *lrange, off_t voff);

void silofs_lrange128_reset(struct silofs_lrange128 *vrng);

void silofs_lrange128_htox(struct silofs_lrange128    *vrng,
                           const struct silofs_lrange *lrange);

void silofs_lrange128_xtoh(const struct silofs_lrange128 *vrng,
                           struct silofs_lrange          *lrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_space_span(enum silofs_height height);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* uaddr */

/* logical addressing of space-mapping nodes */
struct silofs_uaddr {
	struct silofs_laddr laddr;
	off_t               voff;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_uaddr_none(void);

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr);

void silofs_uaddr_reset(struct silofs_uaddr *uaddr);

void silofs_uaddr_assign(struct silofs_uaddr       *uaddr,
                         const struct silofs_uaddr *other);

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

const struct silofs_blobid *
silofs_uaddr_blobid(const struct silofs_uaddr *uaddr);

const struct silofs_lsid *silofs_uaddr_lsid(const struct silofs_uaddr *uaddr);

enum silofs_vtype silofs_uaddr_vtype(const struct silofs_uaddr *uaddr);

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr      *uaddr,
                        const struct silofs_lsid *lsid, off_t bpos,
                        off_t voff);

void silofs_uaddr128b_reset(struct silofs_uaddr128b *uaddr128);

void silofs_uaddr128b_htox(struct silofs_uaddr128b   *uaddr128,
                           const struct silofs_uaddr *uaddr);

void silofs_uaddr128b_xtoh(const struct silofs_uaddr128b *uaddr128,
                           struct silofs_uaddr           *uaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vaddr */

/* logical addressing of virtual nodes */
struct silofs_vaddr {
	off_t             off;
	enum silofs_vtype vtype;
};

/* set of addresses within single vblock */
struct silofs_vaddrs {
	struct silofs_vaddr vaddr[SILOFS_NKB_IN_LBK];
	size_t              count;
};

const struct silofs_vaddr *silofs_vaddr_none(void);

size_t silofs_vaddr_len(const struct silofs_vaddr *vaddr);

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

void silofs_vaddr_setup(struct silofs_vaddr *vaddr, enum silofs_vtype vtype,
                        off_t off);

void silofs_vaddr_advance(const struct silofs_vaddr *vaddr, size_t nsteps,
                          struct silofs_vaddr *out_vaddr);

void silofs_vaddr_of_lsmap(struct silofs_vaddr *vaddr,
                           enum silofs_vtype refvtype, off_t off);

void silofs_vaddr_assign(struct silofs_vaddr       *vaddr,
                         const struct silofs_vaddr *other);

void silofs_vaddr_reset(struct silofs_vaddr *vaddr);

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdata64k(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr);

void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_vtype vtype, off_t voff_base,
                            size_t bn, size_t kbn);

void silofs_vaddr56_htox(struct silofs_vaddr56 *vaddr56, off_t off);

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *vaddr56, off_t *out_off);

void silofs_vaddr64_htox(struct silofs_vaddr64     *vaddr64,
                         const struct silofs_vaddr *vaddr);

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vaddr64,
                         struct silofs_vaddr         *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_resolve_spnode2_vaddr(const struct silofs_vaddr *ref_vaddr,
                                  struct silofs_vaddr       *out_vaddr);

void silofs_ino_to_vaddr(ino_t ino, struct silofs_vaddr *out_vaddr);

ino_t silofs_vaddr_to_ino(const struct silofs_vaddr *vaddr);

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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* uidgid */

uid_t silofs_uid_null(void);

uid_t silofs_uid_nobody(void);

bool silofs_uid_eq(uid_t uid1, uid_t uid2);

bool silofs_uid_isnull(uid_t uid);

bool silofs_uid_isroot(uid_t uid);

gid_t silofs_gid_null(void);

gid_t silofs_gid_nobody(void);

bool silofs_gid_eq(gid_t gid1, gid_t gid2);

bool silofs_gid_isnull(gid_t gid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cred_init(struct silofs_cred *cred);

void silofs_cred_fini(struct silofs_cred *cred);

void silofs_cred_assign(struct silofs_cred       *cred,
                        const struct silofs_cred *other);

void silofs_cred_setup(struct silofs_cred *cred, //
                       uid_t uid, gid_t gid, mode_t umsk);

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
