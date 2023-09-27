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

loff_t silofs_lba_to_off(silofs_lba_t lba);

silofs_lba_t silofs_lba_plus(silofs_lba_t lba, size_t nbk);

silofs_lba_t silofs_off_to_lba(loff_t off);

loff_t silofs_off_in_lbk(loff_t off);

loff_t silofs_off_to_spleaf_start(loff_t voff);

loff_t silofs_off_to_spleaf_next(loff_t voff);

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

bool silofs_stype_isunode(enum silofs_stype stype);

bool silofs_stype_isvnode(enum silofs_stype stype);

bool silofs_stype_isdata(enum silofs_stype stype);

uint32_t silofs_stype_size(enum silofs_stype stype);

ssize_t silofs_stype_ssize(enum silofs_stype stype);

size_t silofs_stype_nkbs(enum silofs_stype stype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_blobid *silofs_blobid_none(void);

size_t silofs_blobid_size(const struct silofs_blobid *blobid);

loff_t silofs_blobid_pos(const struct silofs_blobid *blobid, loff_t off);

bool silofs_blobid_isnull(const struct silofs_blobid *blobid);

bool silofs_blobid_has_treeid(const struct silofs_blobid *blobid,
                              const struct silofs_treeid *treeid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other);

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

uint64_t silofs_blobid_hash64(const struct silofs_blobid *blobid);


void silofs_blobid_setup(struct silofs_blobid *blobid,
                         const struct silofs_treeid *treeid,
                         loff_t voff, enum silofs_stype vspace,
                         enum silofs_height height);

void silofs_blobid40b_reset(struct silofs_blobid40b *blobid40);

void silofs_blobid40b_set(struct silofs_blobid40b *blobid40,
                          const struct silofs_blobid *blobid);

void silofs_blobid40b_parse(const struct silofs_blobid40b *blobid40,
                            struct silofs_blobid *blobid);


int silofs_blobid_to_name(const struct silofs_blobid *blobid,
                          char *name, size_t nmax, size_t *out_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_paddr *silofs_paddr_none(void);

void silofs_paddr_setup(struct silofs_paddr *paddr,
                        const struct silofs_blobid *blobid,
                        loff_t off, size_t len);

void silofs_paddr_of_bk(struct silofs_paddr *paddr,
                        const struct silofs_blobid *blobid, silofs_lba_t lba);

void silofs_paddr_reset(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

void silofs_paddr_as_iv(const struct silofs_paddr *paddr,
                        struct silofs_iv *out_iv);

bool silofs_paddr_same_tree(const struct silofs_paddr *paddr,
                            const struct silofs_paddr *other);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

bool silofs_paddr_isvalid(const struct silofs_paddr *paddr);

bool silofs_paddr_isequal(const struct silofs_paddr *paddr,
                          const struct silofs_paddr *other);

void silofs_paddr48b_set(struct silofs_paddr48b *paddr48,
                         const struct silofs_paddr *paddr);

void silofs_paddr48b_parse(const struct silofs_paddr48b *paddr48,
                           struct silofs_paddr *paddr);

void silofs_paddr48b_reset(struct silofs_paddr48b *paddr48);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_bkaddr *silofs_bkaddr_none(void);

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr);

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_blobid *blobid, silofs_lba_t lba);

void  silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                           const struct silofs_blobid *blobid, loff_t off);

void silofs_bkaddr_by_paddr(struct silofs_bkaddr *bkaddr,
                            const struct silofs_paddr *paddr);

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other);

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2);

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other);

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_treeid_generate(struct silofs_treeid *treeid);

bool silofs_treeid_isequal(const struct silofs_treeid *treeid1,
                           const struct silofs_treeid *treeid2);

void silofs_treeid_as_u128(const struct silofs_treeid *treeid,
                           uint64_t *out_u1, uint64_t *out_u2);

void silofs_treeid128_set(struct silofs_treeid128 *treeid128,
                          const struct silofs_treeid *treeid);

void silofs_treeid128_parse(const struct silofs_treeid128 *treeid128,
                            struct silofs_treeid *treeid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_plink_assign(struct silofs_plink *plink,
                         const struct silofs_plink *other);

void silofs_plink_assign2(struct silofs_plink *plink,
                          const struct silofs_paddr *paddr,
                          const struct silofs_iv *riv);

void silofs_plink_setup(struct silofs_plink *plink,
                        const struct silofs_blink *blink,
                        const struct silofs_vaddr *vaddr);

void silofs_plink_reset(struct silofs_plink *plink);

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

const struct silofs_blobid *
silofs_uaddr_blobid(const struct silofs_uaddr *uaddr);

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr *uaddr,
                        const struct silofs_blobid *blobid,
                        loff_t bpos, enum silofs_stype stype, loff_t voff);

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64);

void silofs_uaddr64b_set(struct silofs_uaddr64b *uaddr64,
                         const struct silofs_uaddr *uaddr);

void silofs_uaddr64b_parse(const struct silofs_uaddr64b *uaddr64,
                           struct silofs_uaddr *uaddr);


void silofs_ulink_assign(struct silofs_ulink *ulink,
                         const struct silofs_ulink *other);

void silofs_ulink_assign2(struct silofs_ulink *ulink,
                          const struct silofs_uaddr *uaddr,
                          const struct silofs_iv *iv);

void silofs_ulink_reset(struct silofs_ulink *ulink);

void silofs_ulink_as_plink(const struct silofs_ulink *ulink,
                           struct silofs_plink *out_plink);

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

void silofs_vaddr56_set(struct silofs_vaddr56 *va, loff_t off);

loff_t silofs_vaddr56_parse(const struct silofs_vaddr56 *va);

void silofs_vaddr64_set(struct silofs_vaddr64 *vadr,
                        const struct silofs_vaddr *vaddr);

void silofs_vaddr64_parse(const struct silofs_vaddr64 *vadr,
                          struct silofs_vaddr *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_blob_size(enum silofs_height height);

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

void silofs_vrange128_set(struct silofs_vrange128 *vrng,
                          const struct silofs_vrange *vrange);

void silofs_vrange128_parse(const struct silofs_vrange128 *vrng,
                            struct silofs_vrange *vrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_fs_capacity(size_t cap_size);

int silofs_calc_fs_capacity(size_t capcity_want, size_t *out_capacity);


int silofs_verify_ino(ino_t ino);

int silofs_verify_off(loff_t off);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static inline uint64_t silofs_cpu_to_time(time_t tm)
{
	return silofs_cpu_to_le64((uint64_t)tm);
}

static inline time_t silofs_time_to_cpu(uint64_t tm)
{
	return (time_t)silofs_le64_to_cpu(tm);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline silofs_lba_t silofs_lba_align(silofs_lba_t lba, ssize_t align)
{
	return (lba / align) * align;
}

static inline bool silofs_lba_isequal(silofs_lba_t lba1, silofs_lba_t lba2)
{
	return (lba1 == lba2);
}

static inline bool silofs_lba_isnull(silofs_lba_t lba)
{
	return silofs_lba_isequal(lba, SILOFS_LBA_NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_off_isnull(loff_t off)
{
	return (off < 0);
}

static inline loff_t silofs_off_min(loff_t off1, loff_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

static inline loff_t silofs_off_max(loff_t off1, loff_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

static inline loff_t silofs_off_max3(loff_t off1, loff_t off2, loff_t off3)
{
	return silofs_off_max(silofs_off_max(off1, off2), off3);
}

static inline loff_t silofs_off_end(loff_t off, size_t len)
{
	return off + (loff_t)len;
}

static inline loff_t silofs_off_clamp(loff_t off1, loff_t off2, loff_t off3)
{
	return silofs_off_min(silofs_off_max(off1, off2), off3);
}

static inline loff_t silofs_off_align(loff_t off, ssize_t align)
{
	return (off / align) * align;
}

static inline loff_t silofs_off_align_to_lbk(loff_t off)
{
	return silofs_off_align(off, SILOFS_LBK_SIZE);
}

static inline loff_t silofs_off_next(loff_t off, ssize_t len)
{
	return silofs_off_align(off + len, len);
}

static inline loff_t silofs_off_next_n(loff_t off, ssize_t len, size_t n)
{
	return silofs_off_align(off + ((ssize_t)n * len), len);
}

static inline loff_t silofs_off_next_lbk(loff_t off)
{
	return silofs_off_next(off, SILOFS_LBK_SIZE);
}

static inline ssize_t silofs_off_diff(loff_t beg, loff_t end)
{
	return end - beg;
}

static inline ssize_t silofs_off_len(loff_t beg, loff_t end)
{
	return silofs_off_diff(beg, end);
}

static inline size_t silofs_off_ulen(loff_t beg, loff_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

static inline bool silofs_off_iswithin(loff_t off, loff_t beg, loff_t end)
{
	return (beg <= off) && (off < end);
}

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
