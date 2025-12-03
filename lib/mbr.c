/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <silofs/ondisk.h>
#include "infra.h"
#include "crypt.h"
#include "bstore.h"
#include "mbr.h"
#include "fs.h"
#include "env.h"

static uint64_t mbr1k_magic(const struct silofs_mbr1k *mbr1k)
{
	return silofs_le64_to_cpu(mbr1k->mbr_magic);
}

static void mbr1k_set_magic(struct silofs_mbr1k *mbr1k, uint64_t magic)
{
	mbr1k->mbr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t mbr1k_version(const struct silofs_mbr1k *mbr1k)
{
	return silofs_le64_to_cpu(mbr1k->mbr_version);
}

static void mbr1k_set_version(struct silofs_mbr1k *mbr1k, uint64_t version)
{
	mbr1k->mbr_version = silofs_cpu_to_le64(version);
}

static uint32_t mbr1k_flags(const struct silofs_mbr1k *mbr1k)
{
	return silofs_le32_to_cpu(mbr1k->mbr_flags);
}

static void mbr1k_set_flags(struct silofs_mbr1k *mbr1k, uint32_t flags)
{
	mbr1k->mbr_flags = silofs_cpu_to_le32(flags);
}

static enum silofs_mbr_kind mbr1k_kind(const struct silofs_mbr1k *mbr1k)
{
	const uint32_t mbr_kind = silofs_le32_to_cpu(mbr1k->mbr_kind);

	return (enum silofs_mbr_kind)mbr_kind;
}

static void
mbr1k_set_kind(struct silofs_mbr1k *mbr1k, enum silofs_mbr_kind mbr_kind)
{
	mbr1k->mbr_kind = silofs_cpu_to_le32((uint32_t)mbr_kind);
}

static void
mbr1k_root(const struct silofs_mbr1k *mbr1k, struct silofs_pmeta *out_pmeta)
{
	silofs_pmeta192b_xtoh(&mbr1k->mbr_root, out_pmeta);
}

static void
mbr1k_set_root(struct silofs_mbr1k *mbr1k, const struct silofs_pmeta *pmeta)
{
	silofs_pmeta192b_htox(&mbr1k->mbr_root, pmeta);
}

static void mbr1k_reset_root(struct silofs_mbr1k *mbr1k)
{
	mbr1k_set_root(mbr1k, silofs_pmeta_none());
}

static void mbr1k_sb_addr(const struct silofs_mbr1k *mbr1k,
                          struct silofs_uaddr *out_sb_addr)
{
	silofs_uaddr128b_xtoh(&mbr1k->mbr_sb_addr, out_sb_addr);
}

static void mbr1k_set_sb_addr(struct silofs_mbr1k *mbr1k,
                              const struct silofs_uaddr *sb_addr)
{
	silofs_uaddr128b_htox(&mbr1k->mbr_sb_addr, sb_addr);
}

static void mbr1k_setup(struct silofs_mbr1k *mbr1k)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_REVISION);
	mbr1k_reset_root(mbr1k);
}

static int mbr1k_check_base(const struct silofs_mbr1k *mbr1k)
{
	const uint64_t magic = mbr1k_magic(mbr1k);
	const uint64_t version = mbr1k_version(mbr1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_MBR_MAGIC) && (version != SILOFS_FMT_REVISION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad mbr magic: 0x%lx", magic);
		return -SILOFS_EBADMBR;
	}
	if (version != SILOFS_FMT_REVISION) {
		log_dbg("bad mbr version: %lu", version);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int mbr1k_check_uaddr_sb(const struct silofs_mbr1k *mbr1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_mtype mtype;

	mbr1k_sb_addr(mbr1k, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	height = silofs_uaddr_height(&uaddr);
	mtype = silofs_uaddr_mtype(&uaddr);
	if ((mtype != SILOFS_MTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad mbr uaddr-sb: voff=%ld mtype=%d height=%d",
		        uaddr.voff, (int)mtype, (int)height);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static void
mbr1k_uuid(const struct silofs_mbr1k *mbr1k, struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &mbr1k->mbr_uuid);
}

static void
mbr1k_set_uuid(struct silofs_mbr1k *mbr1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&mbr1k->mbr_uuid, uuid);
}

static void mbr1k_gen_uuid(struct silofs_mbr1k *mbr1k)
{
	struct silofs_uuid uuid;

	silofs_uuid_generate(&uuid);
	mbr1k_set_uuid(mbr1k, &uuid);
}

static int mbr1k_check(const struct silofs_mbr1k *mbr1k)
{
	struct silofs_pmeta pmeta;
	int err;

	err = mbr1k_check_base(mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_check_uaddr_sb(mbr1k);
	if (err) {
		return err;
	}
	mbr1k_root(mbr1k, &pmeta);
	err = silofs_ciargs_check(&pmeta.cmeta.ciargs);
	if (err) {
		return err;
	}
	return 0;
}

static void
mbr1k_hash(const struct silofs_mbr1k *mbr1k, struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(&mbr1k->mbr_hash, hash);
}

static void
mbr1k_set_hash(struct silofs_mbr1k *mbr1k, const struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(hash, &mbr1k->mbr_hash);
}

static void mbr1k_calc_hash(const struct silofs_mbr1k *mbr1k,
                            const struct silofs_mdigest *md,
                            struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_mbr1k, mbr_hash);

	silofs_sha3_256_of(md, mbr1k, len, out_hash);
}

static void
mbr1k_stamp(struct silofs_mbr1k *mbr1k, const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	mbr1k_calc_hash(mbr1k, md, &hash);
	mbr1k_set_hash(mbr1k, &hash);
}

static int mbr1k_check_hash(const struct silofs_mbr1k *mbr1k,
                            const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	mbr1k_hash(mbr1k, &hash[0]);
	mbr1k_calc_hash(mbr1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int
mbr1k_verify(const struct silofs_mbr1k *mbr1k, const struct silofs_mdigest *md)
{
	int err;

	err = mbr1k_check(mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_check_hash(mbr1k, md);
	if (err) {
		return err;
	}
	return 0;
}

static void
mbr1k_xtoh(const struct silofs_mbr1k *mbr1k, struct silofs_mbr *mbr)
{
	mbr1k_uuid(mbr1k, &mbr->uuid);
	mbr1k_sb_addr(mbr1k, &mbr->sb_addr);
	mbr1k_root(mbr1k, &mbr->root);
	mbr->kind = mbr1k_kind(mbr1k);
	mbr->flags = mbr1k_flags(mbr1k);
}

static void
mbr1k_htox(struct silofs_mbr1k *mbr1k, const struct silofs_mbr *mbr)
{
	mbr1k_setup(mbr1k);
	mbr1k_set_sb_addr(mbr1k, &mbr->sb_addr);
	mbr1k_set_root(mbr1k, &mbr->root);
	mbr1k_set_kind(mbr1k, mbr->kind);
	mbr1k_set_flags(mbr1k, mbr->flags);
	mbr1k_set_uuid(mbr1k, &mbr->uuid);
}

static void mbr1k_init(struct silofs_mbr1k *mbr1k, enum silofs_mbr_kind kind)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_REVISION);
	mbr1k_reset_root(mbr1k);
	mbr1k_set_kind(mbr1k, kind);
	mbr1k_set_flags(mbr1k, 0);
	mbr1k_gen_uuid(mbr1k);
}

static void mbr1k_fini(struct silofs_mbr1k *mbr1k)
{
	silofs_memffff(mbr1k, sizeof(*mbr1k));
}

static int mbr1k_encrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher *cipher,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	return silofs_encrypt_buf(cipher, civkey, mbr1k, out_mbr1k,
	                          sizeof(*out_mbr1k));
}

static int mbr1k_decrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher *cipher,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	return silofs_decrypt_buf(cipher, civkey, mbr1k, out_mbr1k,
	                          sizeof(*out_mbr1k));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mbr_gen_uuid(struct silofs_mbr *mbr)
{
	silofs_uuid_generate(&mbr->uuid);
}

static bool
mbr_has_sb_addr(const struct silofs_mbr *mbr, const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_isequal(&mbr->sb_addr, uaddr);
}

static void
mbr_set_sb_addr(struct silofs_mbr *mbr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&mbr->sb_addr, uaddr);
}

int silofs_mbr_root(const struct silofs_mbr *mbr,
                    struct silofs_pmeta *out_pmeta)
{
	silofs_pmeta_assign(out_pmeta, &mbr->root);
	return silofs_pmeta_isnull(out_pmeta) ? -SILOFS_ENOENT : 0;
}

void silofs_mbr_set_root(struct silofs_mbr *mbr,
                         const struct silofs_pmeta *pmeta)
{
	silofs_pmeta_assign(&mbr->root, pmeta);
}

static void
mbr_set_rootc(struct silofs_mbr *mbr, const struct silofs_cmeta *cmeta)
{
	silofs_cmeta_assign(&mbr->root.cmeta, cmeta);
}

void silofs_mbr_set_rootc_by(struct silofs_mbr *mbr,
                             const struct silofs_mbr *other)
{
	mbr_set_rootc(mbr, &other->root.cmeta);
}

void silofs_mbr_init(struct silofs_mbr *mbr, enum silofs_mbr_kind kind)
{
	silofs_memzero(mbr, sizeof(*mbr));
	silofs_pmeta_reset(&mbr->root);
	silofs_uaddr_reset(&mbr->sb_addr);
	mbr_gen_uuid(mbr);
	mbr->kind = kind;
	mbr->flags = 0;
}

void silofs_mbr_fini(struct silofs_mbr *mbr)
{
	silofs_uaddr_reset(&mbr->sb_addr);
	silofs_pmeta_reset(&mbr->root);
	mbr->kind = SILOFS_MBR_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
mbr_encode(const struct silofs_mbr *mbr, const struct silofs_mdigest *mdigest,
           const struct silofs_cipher *cipher,
           const struct silofs_civkey *civkey, struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbr1k mbr1k;

	mbr1k_htox(&mbr1k, mbr);
	mbr1k_stamp(&mbr1k, mdigest);
	return mbr1k_encrypt(&mbr1k, cipher, civkey, out_mbr1k);
}

static int mbr_decode(struct silofs_mbr *mbr, //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_civkey *civkey,
                      const struct silofs_mbr1k *enc_mbr1k)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 1 };
	int err;

	err = mbr1k_decrypt(enc_mbr1k, cipher, civkey, &mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_verify(&mbr1k, mdigest);
	if (err) {
		return err;
	}
	mbr1k_xtoh(&mbr1k, mbr);
	return 0;
}

void silofs_mbr_update_sb(struct silofs_mbr *mbr,
                          const struct silofs_uaddr *sb_uaddr)
{
	if (!mbr_has_sb_addr(mbr, sb_uaddr)) {
		mbr_set_sb_addr(mbr, sb_uaddr);
		mbr_gen_uuid(mbr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* auxiliary controller for MBR operations */
struct silofs_mbraux {
	struct silofs_mdigest mdigest;
	struct silofs_cipher cipher;
	struct silofs_cmeta cmeta;
};

static int
mbraux_init(struct silofs_mbraux *aux, const struct silofs_cmeta *cmeta)
{
	int err;

	err = silofs_mdigest_init(&aux->mdigest);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&aux->cipher);
	if (err) {
		silofs_mdigest_fini(&aux->mdigest);
		return err;
	}
	silofs_cmeta_assign(&aux->cmeta, cmeta);
	return 0;
}

static void mbraux_fini(struct silofs_mbraux *aux)
{
	silofs_cmeta_reset(&aux->cmeta);
	silofs_cipher_fini(&aux->cipher);
	silofs_mdigest_fini(&aux->mdigest);
}

static int
mbraux_encode_mbr(struct silofs_mbraux *aux, const struct silofs_mbr *mbr,
                  struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(mbr, &aux->mdigest, &aux->cipher, &aux->cmeta.civkey,
	                  out_mbr1k);
}

static int
mbraux_encode_mbr1k(struct silofs_mbraux *aux, struct silofs_mbr1k *mbr1k,
                    struct silofs_mbr1k *out_mbr1k)
{
	mbr1k_stamp(mbr1k, &aux->mdigest);
	return mbr1k_encrypt(mbr1k, &aux->cipher, &aux->cmeta.civkey,
	                     out_mbr1k);
}

static void mbraux_calc_paddr_of(struct silofs_mbraux *aux,
                                 const struct silofs_mbr1k *mbr1k,
                                 struct silofs_paddr *out_paddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(mbr1k),
		.iov_len = sizeof(*mbr1k),
	};

	silofs_calc_cas_paddr(&aux->mdigest, SILOFS_MTYPE_MBR, &iov, 1,
	                      out_paddr);
}

static int mbraux_verify_paddr(struct silofs_mbraux *aux,
                               const struct silofs_paddr *paddr,
                               const struct silofs_mbr1k *mbr1k)
{
	struct silofs_paddr calc_paddr;

	mbraux_calc_paddr_of(aux, mbr1k, &calc_paddr);
	return silofs_paddr_isequal(paddr, &calc_paddr) ? 0 : -SILOFS_EBADMBR;
}

static int mbraux_decode_mbr(struct silofs_mbraux *aux, struct silofs_mbr *mbr,
                             const struct silofs_mbr1k *mbr1k)
{
	return mbr_decode(mbr, &aux->mdigest, &aux->cipher, &aux->cmeta.civkey,
	                  mbr1k);
}

static int mbraux_decode_mbr1k(struct silofs_mbraux *aux,
                               const struct silofs_mbr1k *mbr1k,
                               struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbr1k_decrypt(mbr1k, &aux->cipher, &aux->cmeta.civkey,
	                    out_mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_verify(mbr1k, &aux->mdigest);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_mbr_encode_by(const struct silofs_mbr *mbr,
                         const struct silofs_cmeta *cmeta,
                         struct silofs_paddr *out_paddr,
                         struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, cmeta);
	if (err) {
		return err;
	}
	err = mbraux_encode_mbr(&aux, mbr, out_mbr1k);
	if (err) {
		goto out;
	}
	mbraux_calc_paddr_of(&aux, out_mbr1k, out_paddr);
out:
	mbraux_fini(&aux);
	return err;
}

int silofs_mbr_decode_by(struct silofs_mbr *mbr,
                         const struct silofs_cmeta *cmeta,
                         const struct silofs_paddr *paddr,
                         const struct silofs_mbr1k *mbr1k)
{
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, cmeta);
	if (err) {
		return err;
	}
	err = mbraux_verify_paddr(&aux, paddr, mbr1k);
	if (err) {
		goto out;
	}
	err = mbraux_decode_mbr(&aux, mbr, mbr1k);
out:
	mbraux_fini(&aux);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_derive_mbr_cmeta(const struct silofs_password *passwd,
                            struct silofs_cmeta *out_cmeta)
{
	struct silofs_civkey civkey;
	struct silofs_mdigest mdigest;
	int err;

	silofs_cmeta_reset(out_cmeta);
	if ((passwd == nullptr) || (passwd->passlen == 0)) {
		return 0;
	}
	err = silofs_mdigest_init(&mdigest);
	if (err) {
		return err;
	}
	err = silofs_derive_default_civkey(&mdigest, passwd, &civkey);
	if (err) {
		goto out;
	}
	silofs_cmeta_setup(out_cmeta, &civkey);
out:
	silofs_mdigest_fini(&mdigest);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static enum silofs_mtype pmeta_mtype(const struct silofs_pmeta *pmeta)
{
	return pmeta->paddr.mtype;
}

static bool pmeta_isuber(const struct silofs_pmeta *pmeta)
{
	return (pmeta_mtype(pmeta) == SILOFS_MTYPE_UBER);
}

static bool pmeta_isarix(const struct silofs_pmeta *pmeta)
{
	return (pmeta_mtype(pmeta) == SILOFS_MTYPE_ARIX);
}

void silofs_mbi_init(struct silofs_mbr_info *mbi, enum silofs_mbr_kind kind)
{
	silofs_cmeta_reset(&mbi->mb_cmeta);
	mbr1k_init(&mbi->mb_mbr1k, kind);
}

void silofs_mbi_fini(struct silofs_mbr_info *mbi)
{
	silofs_cmeta_reset(&mbi->mb_cmeta);
	mbr1k_fini(&mbi->mb_mbr1k);
}

int silofs_mbi_update_cmeta_by(struct silofs_mbr_info *mbi,
                               const struct silofs_password *pw)
{
	return silofs_derive_mbr_cmeta(pw, &mbi->mb_cmeta);
}

int silofs_mbi_uber_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta *out_pmeta)
{
	const struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;
	const enum silofs_mbr_kind kind = mbr1k_kind(mbr1k);

	if (kind != SILOFS_MBR_FS) {
		return -SILOFS_ENOENT;
	}
	mbr1k_root(mbr1k, out_pmeta);
	if (!pmeta_isuber(out_pmeta)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_mbi_arix_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pmeta *out_pmeta)
{
	const struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;
	const enum silofs_mbr_kind kind = mbr1k_kind(mbr1k);

	if (kind != SILOFS_MBR_FS) {
		return -SILOFS_ENOENT;
	}
	mbr1k_root(mbr1k, out_pmeta);
	if (!pmeta_isarix(out_pmeta)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_mbi_set_root(struct silofs_mbr_info *mbi,
                        const struct silofs_pmeta *pmeta)
{
	struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;
	const enum silofs_mbr_kind kind = mbr1k_kind(mbr1k);

	if ((kind == SILOFS_MBR_FS) && !pmeta_isuber(pmeta)) {
		return -SILOFS_EINVAL;
	}
	if ((kind == SILOFS_MBR_AR) && !pmeta_isarix(pmeta)) {
		return -SILOFS_EINVAL;
	}
	mbr1k_set_root(mbr1k, pmeta);
	return 0;
}

int silofs_mbi_set_sbaddr(struct silofs_mbr_info *mbi,
                          const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;
	const enum silofs_mbr_kind kind = mbr1k_kind(mbr1k);

	if (kind != SILOFS_MBR_FS) {
		return -SILOFS_EINVAL;
	}
	mbr1k_set_sb_addr(&mbi->mb_mbr1k, sb_uaddr);
	return 0;
}

void silofs_mbi_align_cmeta(struct silofs_mbr_info *mbi,
                            const struct silofs_mbr_info *other)
{
	silofs_cmeta_assign(&mbi->mb_cmeta, &other->mb_cmeta);
}

int silofs_mbi_stamp_export(struct silofs_mbr_info *mbi,
                            struct silofs_paddr *out_paddr,
                            struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, &mbi->mb_cmeta);
	if (err) {
		return err;
	}
	err = mbraux_encode_mbr1k(&aux, &mbi->mb_mbr1k, out_mbr1k);
	if (err) {
		goto out;
	}
	mbraux_calc_paddr_of(&aux, out_mbr1k, out_paddr);
out:
	mbraux_fini(&aux);
	return err;
}

int silofs_mbi_verify_import(struct silofs_mbr_info *mbi,
                             const struct silofs_paddr *paddr,
                             const struct silofs_mbr1k *mbr1k)
{
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, &mbi->mb_cmeta);
	if (err) {
		return err;
	}
	err = mbraux_verify_paddr(&aux, paddr, mbr1k);
	if (err) {
		return err;
	}
	err = mbraux_decode_mbr1k(&aux, mbr1k, &mbi->mb_mbr1k);
	if (err) {
		goto out;
	}
out:
	mbraux_fini(&aux);
	return err;
}
