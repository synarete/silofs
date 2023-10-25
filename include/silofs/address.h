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
#ifndef SILOFS_ADDRESS_H_
#define SILOFS_ADDRESS_H_

#include <silofs/types.h>
#include <stdint.h>
#include <endian.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uint64_to_ascii(uint64_t u, char *a);

uint64_t silofs_ascii_to_uint64(const char *a);

void silofs_hash256_assign(struct silofs_hash256 *hash,
                           const struct silofs_hash256 *other);

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

uint64_t silofs_hash256_to_u64(const struct silofs_hash256 *hash);

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              char *buf, size_t bsz);

void silofs_hash512_assign(struct silofs_hash512 *hash,
                           const struct silofs_hash512 *other);

bool silofs_hash512_isequal(const struct silofs_hash512 *hash,
                            const struct silofs_hash512 *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_stype_isunode(enum silofs_stype stype);

bool silofs_stype_isvnode(enum silofs_stype stype);

bool silofs_stype_isdata(enum silofs_stype stype);

uint32_t silofs_stype_size(enum silofs_stype stype);

ssize_t silofs_stype_ssize(enum silofs_stype stype);

size_t silofs_stype_nkbs(enum silofs_stype stype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *riv);

void silofs_llink_assign(struct silofs_llink *llink,
                         const struct silofs_llink *other);

void silofs_llink_reset(struct silofs_llink *llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_bkaddr *silofs_bkaddr_none(void);

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr);

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_lextid *lextid, silofs_lba_t lba);

void  silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                           const struct silofs_lextid *lextid, loff_t off);

void silofs_bkaddr_by_laddr(struct silofs_bkaddr *bkaddr,
                            const struct silofs_laddr *laddr);

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other);

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2);

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other);

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_uaddr_none(void);

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr);

void silofs_uaddr_reset(struct silofs_uaddr *uaddr);

void silofs_uaddr_assign(struct silofs_uaddr *uaddr,
                         const struct silofs_uaddr *other);

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

const struct silofs_treeid *
silofs_uaddr_treeid(const struct silofs_uaddr *uaddr);

const struct silofs_lextid *
silofs_uaddr_lextid(const struct silofs_uaddr *uaddr);

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_lextid *lextid,
                        loff_t bpos, enum silofs_stype stype, loff_t voff);

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64);

void silofs_uaddr64b_htox(struct silofs_uaddr64b *uaddr64,
                          const struct silofs_uaddr *uaddr);

void silofs_uaddr64b_xtoh(const struct silofs_uaddr64b *uaddr64,
                          struct silofs_uaddr *uaddr);


void silofs_ulink_assign(struct silofs_ulink *ulink,
                         const struct silofs_ulink *other);

void silofs_ulink_assign2(struct silofs_ulink *ulink,
                          const struct silofs_uaddr *uaddr,
                          const struct silofs_iv *iv);

void silofs_ulink_reset(struct silofs_ulink *ulink);

void silofs_ulink_as_llink(const struct silofs_ulink *ulink,
                           struct silofs_llink *out_llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_vaddr *silofs_vaddr_none(void);

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

void silofs_vaddr_setup(struct silofs_vaddr *vaddr,
                        enum silofs_stype stype, loff_t off);

void silofs_vaddr_setup2(struct silofs_vaddr *vaddr,
                         enum silofs_stype stype, silofs_lba_t lba);

void silofs_vaddr_assign(struct silofs_vaddr *vaddr,
                         const struct silofs_vaddr *other);

void silofs_vaddr_reset(struct silofs_vaddr *vaddr);

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr);


void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_stype stype,
                            loff_t voff_base, size_t bn, size_t kbn);

void silofs_vaddr56_htox(struct silofs_vaddr56 *va, loff_t off);

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *va, loff_t *out_off);

void silofs_vaddr64_htox(struct silofs_vaddr64 *vadr,
                         const struct silofs_vaddr *vaddr);

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vadr,
                         struct silofs_vaddr *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_space_span(enum silofs_height height);

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off);

void silofs_vrange_setup(struct silofs_vrange *vrange,
                         enum silofs_height height, loff_t beg, loff_t end);

void silofs_vrange_setup_sub(struct silofs_vrange *vrange,
                             const struct silofs_vrange *other, loff_t beg);

void silofs_vrange_of_space(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base);

void silofs_vrange_of_spmap(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base);

loff_t silofs_vrange_voff_at(const struct silofs_vrange *vrange, size_t slot);

loff_t silofs_vrange_next(const struct silofs_vrange *vrange, loff_t voff);

void silofs_vrange128_reset(struct silofs_vrange128 *vrng);

void silofs_vrange128_htox(struct silofs_vrange128 *vrng,
                           const struct silofs_vrange *vrange);

void silofs_vrange128_xtoh(const struct silofs_vrange128 *vrng,
                           struct silofs_vrange *vrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_fs_capacity(size_t cap_size);

int silofs_calc_fs_capacity(size_t capcity_want, size_t *out_capacity);


int silofs_verify_ino(ino_t ino);

int silofs_verify_off(loff_t off);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_ino_isnull(ino_t ino)
{
	return (ino == SILOFS_INO_NULL);
}

static inline loff_t silofs_ino_to_off(ino_t ino)
{
	return silofs_ino_isnull(ino) ? SILOFS_OFF_NULL :
	       (loff_t)(ino << SILOFS_INODE_SHIFT);
}

static inline ino_t silofs_off_to_ino(loff_t off)
{
	return silofs_off_isnull(off) ? SILOFS_INO_NULL :
	       (ino_t)(off >> SILOFS_INODE_SHIFT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0043: Map uig/gid "nobody" to host values
 *
 * Do not use hard-coded values to uid/gid "nobody" but resolve to host-local
 * values upon boot.
 */
static inline uid_t silofs_uid_nobody(void)
{
	return 65534;
}

static inline gid_t silofs_gid_nobody(void)
{
	return 65534;
}

static inline bool silofs_uid_eq(uid_t uid1, uid_t uid2)
{
	return (uid1 == uid2);
}

static inline bool silofs_uid_isroot(uid_t uid)
{
	return silofs_uid_eq(uid, 0);
}

static inline bool silofs_gid_eq(gid_t gid1, gid_t gid2)
{
	return (gid1 == gid2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_stype_isequal(enum silofs_stype stype1,
                                        enum silofs_stype stype2)
{
	return (stype1 == stype2);
}

static inline bool silofs_stype_isnone(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_NONE);
}

static inline bool silofs_stype_issuper(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SUPER);
}

static inline bool silofs_stype_isspnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SPNODE);
}

static inline bool silofs_stype_isspleaf(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SPLEAF);
}

static inline bool silofs_stype_isinode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_INODE);
}

static inline bool silofs_stype_isxanode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_XANODE);
}

static inline bool silofs_stype_issymval(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SYMVAL);
}

static inline bool silofs_stype_isdtnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_DTNODE);
}

static inline bool silofs_stype_isftnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_FTNODE);
}

static inline bool silofs_stype_isdatabk(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_DATABK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#endif /* SILOFS_ADDRESS_H_ */
