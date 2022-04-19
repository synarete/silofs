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
#ifndef SILOFS_ADDRESS_H_
#define SILOFS_ADDRESS_H_

#include <silofs/fs/types.h>
#include <stdint.h>
#include <endian.h>

void silofs_uint64_to_ascii(uint64_t u, char *a);

uint64_t silofs_ascii_to_uint64(const char *a);

void silofs_hash256_assign(struct silofs_hash256 *hash,
                           const struct silofs_hash256 *other);

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

uint64_t silofs_hash256_to_u64(const struct silofs_hash256 *hash);

void silofs_hash512_assign(struct silofs_hash512 *hash,
                           const struct silofs_hash512 *other);

bool silofs_hash512_isequal(const struct silofs_hash512 *hash,
                            const struct silofs_hash512 *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu);

void silofs_uuid_assign(struct silofs_uuid *uu1,
                        const struct silofs_uuid *uu2);

void silofs_uuid_name(const struct silofs_uuid *uu, struct silofs_namebuf *nb);


void silofs_namebuf_reset(struct silofs_namebuf *nb);

void silofs_namebuf_assign(struct silofs_namebuf *nb,
                           const struct silofs_namebuf *other);

void silofs_namebuf_assign2(struct silofs_namebuf *nb,
                            const struct silofs_name *name);

void silofs_namebuf_assign_str(struct silofs_namebuf *nb,
                               const struct silofs_namestr *name);

void silofs_namebuf_copyto(const struct silofs_namebuf *nb,
                           struct silofs_name *name);

bool silofs_namebuf_isequal(const struct silofs_namebuf *nb,
                            const struct silofs_namestr *name);

void silofs_namebuf_str(const struct silofs_namebuf *nb,
                        struct silofs_namestr *name);


void silofs_namestr_init(struct silofs_namestr *nstr, const char *name);

bool silofs_namestr_isequal(const struct silofs_namestr *nstr,
                            const struct silofs_namestr *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

loff_t silofs_off_within(loff_t off, size_t bsz);

loff_t silofs_off_in_bk(loff_t off);

loff_t silofs_off_to_vsec_start(loff_t voff);

loff_t silofs_off_to_vsec_next(loff_t voff, size_t nvsec);

loff_t silofs_off_to_spnode_start(loff_t voff);

loff_t silofs_off_to_spnode_next(loff_t voff);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_stype_isunode(enum silofs_stype stype);

bool silofs_stype_isvnode(enum silofs_stype stype);

bool silofs_stype_isdata(enum silofs_stype stype);

size_t silofs_stype_size(enum silofs_stype stype);

ssize_t silofs_stype_ssize(enum silofs_stype stype);

size_t silofs_stype_nkbs(enum silofs_stype stype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_blobid *silofs_blobid_none(void);

size_t silofs_blobid_size(const struct silofs_blobid *blobid);

loff_t silofs_blobid_pos(const struct silofs_blobid *blobid, loff_t off);

bool silofs_blobid_isnull(const struct silofs_blobid *blobid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other);

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

uint64_t silofs_blobid_hkey(const struct silofs_blobid *blobid);

uint64_t silofs_blobid_as_u64(const struct silofs_blobid *blobid);


void silofs_blobid_make_tas(struct silofs_blobid *blobid,
                            const struct silofs_xid *treeid,
                            size_t obj_size, size_t nobjs);

void silofs_blobid_make_cas(struct silofs_blobid *blobid,
                            const struct silofs_hash256 *hash, size_t size);


void silofs_blobid40b_reset(struct silofs_blobid40b *blid);

void silofs_blobid40b_set(struct silofs_blobid40b *blid,
                          const struct silofs_blobid *blobid);

void silofs_blobid40b_parse(const struct silofs_blobid40b *blid,
                            struct silofs_blobid *blobid);


int silofs_blobid_to_name(const struct silofs_blobid *blobid,
                          char *name, size_t nmax, size_t *out_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_packid *silofs_packid_none(void);

bool silofs_packid_isnull(const struct silofs_packid *packid);

void silofs_packid_reset(struct silofs_packid *packid);

void silofs_packid_setup(struct silofs_packid *packid,
                         const struct silofs_blobid *blobid);

void silofs_packid_assign(struct silofs_packid *packid,
                          const struct silofs_packid *other);


void silofs_packid64b_reset(struct silofs_packid64b *paid);

void silofs_packid64b_set(struct silofs_packid64b *paid,
                          const struct silofs_packid *packid);

void silofs_packid64b_parse(const struct silofs_packid64b *paid,
                            struct silofs_packid *packid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_bkaddr *silofs_bkaddr_none(void);

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_blobid *blobid, silofs_lba_t lba);

void  silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                           const struct silofs_blobid *blobid, loff_t off);

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other);

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2);

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_oaddr *silofs_oaddr_none(void);

void silofs_oaddr_setup(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *blobid,
                        loff_t off, size_t len);

void silofs_oaddr_of_bk(struct silofs_oaddr *oaddr,
                        const struct silofs_blobid *blobid, silofs_lba_t lba);

void silofs_oaddr_reset(struct silofs_oaddr *oaddr);

void silofs_oaddr_assign(struct silofs_oaddr *oaddr,
                         const struct silofs_oaddr *other);

long silofs_oaddr_compare(const struct silofs_oaddr *oaddr1,
                          const struct silofs_oaddr *oaddr2);

bool silofs_oaddr_isnull(const struct silofs_oaddr *oaddr);

bool silofs_oaddr_isvalid(const struct silofs_oaddr *oaddr);

bool silofs_oaddr_isequal(const struct silofs_oaddr *oaddr,
                          const struct silofs_oaddr *other);


void silofs_voaddr_setup(struct silofs_voaddr *voa,
                         const struct silofs_vaddr *vaddr,
                         const struct silofs_oaddr *oaddr);

void silofs_voaddr_setup_by(struct silofs_voaddr *voa,
                            const struct silofs_blobid *blobid,
                            const struct silofs_vaddr *vaddr);

void silofs_voaddr_assign(struct silofs_voaddr *voa,
                          const struct silofs_voaddr *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_xid_generate(struct silofs_xid *mid);

uint64_t silofs_xid_as_u64(const struct silofs_xid *mid);

bool silofs_xid_isequal(const struct silofs_xid *mid1,
                        const struct silofs_xid *mid2);

void silofs_xid128_set(struct silofs_xid128 *xid128,
                       const struct silofs_xid *mid);

void silofs_xid128_parse(const struct silofs_xid128 *xid128,
                         struct silofs_xid *mid);

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

silofs_lba_t silofs_uaddr_lba(const struct silofs_uaddr *uaddr);

const struct silofs_blobid *
silofs_uaddr_blobid(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_blobid *blobid, loff_t bpos,
                        enum silofs_stype stype, size_t height, loff_t voff);

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uadr);

void silofs_uaddr64b_set(struct silofs_uaddr64b *uadr,
                         const struct silofs_uaddr *uaddr);

void silofs_uaddr64b_parse(const struct silofs_uaddr64b *uadr,
                           struct silofs_uaddr *uaddr);


void silofs_taddr_setup(struct silofs_taddr *taddr,
                        const struct silofs_xid *tree_id,
                        loff_t voff, size_t height);

void silofs_taddr_by_uaddr(struct silofs_taddr *taddr,
                           const struct silofs_uaddr *uaddr);

bool silofs_taddr_isequal(const struct silofs_taddr *taddr1,
                          const struct silofs_taddr *taddr2);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_vaddr *silofs_vaddr_none(void);

loff_t silofs_vaddr_off(const struct silofs_vaddr *vaddr);

enum silofs_stype silofs_vaddr_stype(const struct silofs_vaddr *vaddr);

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
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

silofs_lba_t silofs_vaddr_lba(const struct silofs_vaddr *vaddr);


void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_stype stype,
                            loff_t voff_base, size_t bn, size_t kbn);

void silofs_vaddr56_set(struct silofs_vaddr56 *va, loff_t off);

loff_t silofs_vaddr56_parse(const struct silofs_vaddr56 *va);

void silofs_vaddr64_set(struct silofs_vaddr64 *vadr,
                        const struct silofs_vaddr *vaddr);

void silofs_vaddr64_parse(const struct silofs_vaddr64 *vadr,
                          struct silofs_vaddr *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off);

void silofs_vrange_setup(struct silofs_vrange *vrange,
                         size_t height, loff_t beg, loff_t end);

void silofs_vrange_setup_sub(struct silofs_vrange *vrange,
                             const struct silofs_vrange *other, loff_t beg);

void silofs_vrange_setup_by(struct silofs_vrange *vrange,
                            size_t height, loff_t voff_base);

void silofs_vrange_of_spnode(struct silofs_vrange *vrange,
                             size_t height, loff_t voff);

void silofs_vrange_of_spleaf(struct silofs_vrange *vrange, loff_t voff);

void silofs_vrange128_reset(struct silofs_vrange128 *vrng);

void silofs_vrange128_set(struct silofs_vrange128 *vrng,
                          const struct silofs_vrange *vrange);

void silofs_vrange128_parse(const struct silofs_vrange128 *vrng,
                            struct silofs_vrange *vrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_fs_capacity(size_t cap_size);

int silofs_calc_fs_capacity(size_t capcity_want, size_t *out_capacity);


int silofs_verify_ino(ino_t ino);

int silofs_verify_off(loff_t off);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline uint16_t silofs_cpu_to_le16(uint16_t n)
{
	return htole16(n);
}

static inline uint16_t silofs_le16_to_cpu(uint16_t n)
{
	return le16toh(n);
}

static inline uint32_t silofs_cpu_to_le32(uint32_t n)
{
	return htole32(n);
}

static inline uint32_t silofs_le32_to_cpu(uint32_t n)
{
	return le32toh(n);
}

static inline uint64_t silofs_cpu_to_le64(uint64_t n)
{
	return htole64(n);
}

static inline uint64_t silofs_le64_to_cpu(uint64_t n)
{
	return le64toh(n);
}

static inline uint64_t silofs_cpu_to_ino(ino_t ino)
{
	return silofs_cpu_to_le64(ino);
}

static inline ino_t silofs_ino_to_cpu(uint64_t ino)
{
	return (ino_t)silofs_le64_to_cpu(ino);
}

static inline int64_t silofs_cpu_to_off(loff_t off)
{
	return (int64_t)silofs_cpu_to_le64((uint64_t)off);
}

static inline loff_t silofs_off_to_cpu(int64_t off)
{
	return (loff_t)silofs_le64_to_cpu((uint64_t)off);
}

static inline uint64_t silofs_cpu_to_lba(silofs_lba_t lba)
{
	return silofs_cpu_to_le64((uint64_t)lba);
}

static inline silofs_lba_t silofs_lba_to_cpu(uint64_t lba)
{
	return (silofs_lba_t)silofs_le64_to_cpu(lba);
}


#endif /* SILOFS_ADDRESS_H_ */
