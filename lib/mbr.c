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
#include <silofs/configs.h>
#include <silofs/ondisk.h>
#include "infra.h"
#include "bs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

static bool pnptr_isuber(const struct silofs_pnptr *pnptr)
{
	return pnptr->paddr.blobid.stype.ptype == SILOFS_PTYPE_UBER;
}

static bool pnptr_isarix(const struct silofs_pnptr *pnptr)
{
	return pnptr->paddr.blobid.stype.vtype == SILOFS_VTYPE_ARIX;
}

static void mbr_meta_assign(struct silofs_mbr_meta *meta,
                            const struct silofs_mbr_meta *other)
{
	silofs_nmeta_assign(&meta->nmeta, &other->nmeta);
	silofs_ckey_assign(&meta->hmac_key, &other->hmac_key);
	meta->mode = other->mode;
}

static void mbr_meta_reset(struct silofs_mbr_meta *meta)
{
	silofs_nmeta_reset(&meta->nmeta);
	silofs_ckey_reset(&meta->hmac_key);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void mbr1k_set_flags(struct silofs_mbr1k *mbr1k, uint32_t flags)
{
	mbr1k->mbr_flags = silofs_cpu_to_le32(flags);
}

static enum silofs_mbr_mode mbr1k_mode(const struct silofs_mbr1k *mbr1k)
{
	const uint32_t mode = silofs_le32_to_cpu(mbr1k->mbr_mode);

	return (enum silofs_mbr_mode)mode;
}

static void
mbr1k_set_mode(struct silofs_mbr1k *mbr1k, enum silofs_mbr_mode mode)
{
	mbr1k->mbr_mode = silofs_cpu_to_le32((uint32_t)mode);
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

static void
mbr1k_root(const struct silofs_mbr1k *mbr1k, struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr192b_xtoh(&mbr1k->mbr_root, out_pnptr);
}

static void
mbr1k_set_root(struct silofs_mbr1k *mbr1k, const struct silofs_pnptr *pnptr)
{
	silofs_pnptr192b_htox(&mbr1k->mbr_root, pnptr);
}

static void mbr1k_reset_root(struct silofs_mbr1k *mbr1k)
{
	mbr1k_set_root(mbr1k, silofs_pnptr_none());
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

static int mbr1k_check_base(const struct silofs_mbr1k *mbr1k)
{
	const uint64_t magic   = mbr1k_magic(mbr1k);
	const uint64_t version = mbr1k_version(mbr1k);
	int err = 0, errcnt = 0;

	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad mbr magic: 0x%lx", magic);
		err = -SILOFS_EBADMBR;
		errcnt++;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad mbr version: %lu", version);
		err = -SILOFS_EBADMBR;
		errcnt++;
	}
	/*
	 * When both magic and version are no valid, we assume it is most likely
	 * due to bad password provided by user.
	 */
	return (errcnt == 2) ? -SILOFS_EKEYEXPIRED : err;
}

static int mbr1k_check_uaddr_sb(const struct silofs_mbr1k *mbr1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_vtype vtype;

	mbr1k_sb_addr(mbr1k, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	height = silofs_uaddr_height(&uaddr);
	vtype  = silofs_uaddr_vtype(&uaddr);
	if ((vtype != SILOFS_VTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad mbr uaddr-sb: voff=%ld vtype=%d height=%d",
		        uaddr.voff, (int)vtype, (int)height);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int mbr1k_check_root(const struct silofs_mbr1k *mbr1k)
{
	struct silofs_pnptr pnptr;

	mbr1k_root(mbr1k, &pnptr);
	return silofs_ciargs_check(&pnptr.nmeta.ciargs);
}

static int mbr1k_check(const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbr1k_check_base(mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_check_uaddr_sb(mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_check_root(mbr1k);
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
                            const struct silofs_mdigest_hd *md,
                            struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_mbr1k, mbr_hash);

	silofs_sha3_256_of(md, mbr1k, len, out_hash);
}

static void
mbr1k_stamp(struct silofs_mbr1k *mbr1k, const struct silofs_mdigest_hd *md)
{
	struct silofs_hash256 hash;

	mbr1k_calc_hash(mbr1k, md, &hash);
	mbr1k_set_hash(mbr1k, &hash);
}

static int mbr1k_check_hash(const struct silofs_mbr1k *mbr1k,
                            const struct silofs_mdigest_hd *md)
{
	struct silofs_hash256 hash[2];

	mbr1k_hash(mbr1k, &hash[0]);
	mbr1k_calc_hash(mbr1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int mbr1k_verify(const struct silofs_mbr1k *mbr1k,
                        const struct silofs_mdigest_hd *md)
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

static void mbr1k_init(struct silofs_mbr1k *mbr1k, enum silofs_mbr_mode mode)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_VERSION);
	mbr1k_reset_root(mbr1k);
	mbr1k_set_mode(mbr1k, mode);
	mbr1k_set_flags(mbr1k, 0);
	mbr1k_gen_uuid(mbr1k);
}

static void mbr1k_fini(struct silofs_mbr1k *mbr1k)
{
	silofs_memffff(mbr1k, sizeof(*mbr1k));
}

static size_t mbr1k_enclen(void)
{
	return offsetof(struct silofs_mbr1k, mbr_hmac);
}

static int mbr1k_encrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	return silofs_encrypt_buf(ci_hd, civkey, mbr1k, out_mbr1k,
	                          mbr1k_enclen());
}

static int mbr1k_decrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	return silofs_decrypt_buf(ci_hd, civkey, mbr1k, out_mbr1k,
	                          mbr1k_enclen());
}

static int
mbr1k_calc_hmac(const struct silofs_mbr1k *mbr1k,
                struct silofs_hmac_hd *hmac_hd, const struct silofs_ckey *key,
                struct silofs_mac *out_hmac)
{
	return silofs_hmac_calc(hmac_hd, key, mbr1k, mbr1k_enclen(), out_hmac);
}

static int
mbr1k_assign_hmac(struct silofs_mbr1k *mbr1k, struct silofs_hmac_hd *hmac_hd,
                  const struct silofs_ckey *key)
{
	return mbr1k_calc_hmac(mbr1k, hmac_hd, key, &mbr1k->mbr_hmac);
}

static int
mbr1k_check_hmac(const struct silofs_mbr1k *mbr1k,
                 struct silofs_hmac_hd *hmac_hd, const struct silofs_ckey *key)
{
	struct silofs_mac hmac;
	int err;

	err = mbr1k_calc_hmac(mbr1k, hmac_hd, key, &hmac);
	if (err) {
		return err;
	}
	if (!silofs_mac_isequal(&hmac, &mbr1k->mbr_hmac)) {
		return -SILOFS_EBADMBR;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* auxiliary controller for MBR operations */
struct silofs_mbraux {
	struct silofs_mdigest_hd md_hd;
	struct silofs_hmac_hd hmac_hd;
	struct silofs_cipher_hd ci_hd;
	const struct silofs_mbr_meta *meta;
};

static void mbraux_fini(struct silofs_mbraux *aux)
{
	silofs_cipher_fini(&aux->ci_hd);
	silofs_hmac_fini(&aux->hmac_hd);
	silofs_mdigest_fini(&aux->md_hd);
	aux->meta = nullptr;
}

static int
mbraux_init(struct silofs_mbraux *aux, const struct silofs_mbr_meta *meta)
{
	int err;

	silofs_memzero(aux, sizeof(*aux));
	err = silofs_mdigest_init(&aux->md_hd);
	if (err) {
		goto out_err;
	}
	err = silofs_hmac_init(&aux->hmac_hd);
	if (err) {
		goto out_err;
	}
	err = silofs_cipher_init(&aux->ci_hd);
	if (err) {
		goto out_err;
	}
	aux->meta = meta;
	return 0;
out_err:
	mbraux_fini(aux);
	return err;
}

static int
mbraux_encode_mbr1k(struct silofs_mbraux *aux, struct silofs_mbr1k *mbr1k,
                    struct silofs_mbr1k *out_mbr1k)
{
	int err;

	mbr1k_stamp(mbr1k, &aux->md_hd);
	err = mbr1k_encrypt(mbr1k, &aux->ci_hd, &aux->meta->nmeta.civkey,
	                    out_mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_assign_hmac(out_mbr1k, &aux->hmac_hd,
	                        &aux->meta->hmac_key);
	if (err) {
		return err;
	}
	return 0;
}

static void
mbraux_calc_mbref(struct silofs_mbraux *aux, const struct silofs_mbr1k *mbr1k,
                  struct silofs_mbref *out_mbref)
{
	struct silofs_paddr paddr;
	const struct iovec iov = {
		.iov_base = silofs_unconst(mbr1k),
		.iov_len  = sizeof(*mbr1k),
	};

	silofs_calc_cas_paddr(&aux->md_hd, SILOFS_PTYPE_MBR, SILOFS_VTYPE_NONE,
	                      &iov, 1, &paddr);
	silofs_mbref_derive(out_mbref, &aux->md_hd, &paddr);
}

static int mbraux_verify_mbref(struct silofs_mbraux *aux,
                               const struct silofs_mbref *mbref,
                               const struct silofs_mbr1k *mbr1k)
{
	struct silofs_mbref mbref2;

	mbraux_calc_mbref(aux, mbr1k, &mbref2);
	return silofs_mbref_isequal(mbref, &mbref2) ? 0 : -SILOFS_EBADMBR;
}

static int mbraux_decode_mbr1k(struct silofs_mbraux *aux,
                               const struct silofs_mbr1k *mbr1k,
                               struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbr1k_check_hmac(mbr1k, &aux->hmac_hd, &aux->meta->hmac_key);
	if (err) {
		return err;
	}
	err = mbr1k_decrypt(mbr1k, &aux->ci_hd, &aux->meta->nmeta.civkey,
	                    out_mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_verify(out_mbr1k, &aux->md_hd);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * TODO-0061: Use ARGON2 KDF
 *
 * ARGON2 is considered stronger (GPU-resistant) then PBKDF2 (see [1]) but
 * requires extra wrapping over libgcrypt APIs. Use it.
 *
 * [1] https://fedoraproject.org/wiki/Changes/ \
 *       RemoveFipsModeSetup#Context_information_on_FIPS
 */
static const struct silofs_kdf_descs s_mbr_kdf_descs = {
	.kdf_key = {
		.kd_iterations = 8192,
		.kd_algo = SILOFS_KDF_PBKDF2,
		.kd_subalgo = SILOFS_MD_SHA256,
		.kd_salt_md = SILOFS_MD_SHA3_512,
	},
	.kdf_iv = {
		.kd_iterations = 2048,
		.kd_algo = SILOFS_KDF_SCRYPT,
		.kd_subalgo = 8,
		.kd_salt_md = SILOFS_MD_SHA3_256,
	},
};

static const struct silofs_kdf_desc s_mbr_hmac_kdf_desc = {
	.kd_iterations = 16384,
	.kd_algo       = SILOFS_KDF_SCRYPT,
	.kd_subalgo    = 8,
	.kd_salt_md    = SILOFS_MD_SHA3_256,
};

static int derive_mbr_civkey(const struct silofs_mdigest_hd *md_hd,
                             const struct silofs_password *pw,
                             struct silofs_civkey *out_civkey)
{
	return silofs_derive_civkey(md_hd, pw, &s_mbr_kdf_descs, out_civkey);
}

static int derive_mbr_hmac_ckey(const struct silofs_mdigest_hd *md_hd,
                                const struct silofs_password *pw,
                                struct silofs_ckey *out_key)
{
	return silofs_derive_hmac_key(md_hd, pw, &s_mbr_hmac_kdf_desc,
	                              out_key);
}

int silofs_derive_mbr_meta(const struct silofs_password *passwd,
                           struct silofs_mbr_meta *out_mbr_meta)
{
	struct silofs_civkey civkey;
	struct silofs_mdigest_hd md_hd;
	int err;

	silofs_memzero(out_mbr_meta, sizeof(*out_mbr_meta));
	if ((passwd == nullptr) || (passwd->passlen == 0)) {
		return 0; /* OK -- password-less mode */
	}
	err = silofs_mdigest_init(&md_hd);
	if (err) {
		return err;
	}
	err = derive_mbr_hmac_ckey(&md_hd, passwd, &out_mbr_meta->hmac_key);
	if (err) {
		goto out;
	}
	err = derive_mbr_civkey(&md_hd, passwd, &civkey);
	if (err) {
		goto out;
	}
	silofs_nmeta_setup(&out_mbr_meta->nmeta, &civkey);
out:
	silofs_mdigest_fini(&md_hd);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbi_init(struct silofs_mbr_info *mbi, enum silofs_mbr_mode mode)
{
	const struct silofs_mbr_meta meta_none = {
		.mode = mode,
	};

	mbr_meta_assign(&mbi->mb_meta, &meta_none);
	mbr1k_init(&mbi->mb_mbr1k, mode);
}

void silofs_mbi_fini(struct silofs_mbr_info *mbi)
{
	mbr_meta_reset(&mbi->mb_meta);
	mbr1k_fini(&mbi->mb_mbr1k);
}

static enum silofs_mbr_mode mbi_mode(const struct silofs_mbr_info *mbi)
{
	return mbi->mb_meta.mode;
}

int silofs_mbi_set_meta(struct silofs_mbr_info *mbi,
                        const struct silofs_mbr_meta *meta)
{
	if (meta->mode != mbi_mode(mbi)) {
		return -SILOFS_EINVAL;
	}
	mbr_meta_assign(&mbi->mb_meta, meta);
	return 0;
}

int silofs_mbi_uber_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;

	if (mbi_mode(mbi) != SILOFS_MBR_FS) {
		return -SILOFS_EMBRMODE;
	}
	mbr1k_root(mbr1k, out_pnptr);
	if (!pnptr_isuber(out_pnptr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_mbi_arix_root(const struct silofs_mbr_info *mbi,
                         struct silofs_pnptr *out_pnptr)
{
	const struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;

	if (mbi_mode(mbi) != SILOFS_MBR_AR) {
		return -SILOFS_EMBRMODE;
	}
	mbr1k_root(mbr1k, out_pnptr);
	if (!pnptr_isarix(out_pnptr)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_mbi_set_root(struct silofs_mbr_info *mbi,
                        const struct silofs_pnptr *pnptr)
{
	struct silofs_mbr1k *mbr1k = &mbi->mb_mbr1k;

	if ((mbi_mode(mbi) == SILOFS_MBR_FS) && !pnptr_isuber(pnptr)) {
		return -SILOFS_EMBRMODE;
	}
	if ((mbi_mode(mbi) == SILOFS_MBR_AR) && !pnptr_isarix(pnptr)) {
		return -SILOFS_EMBRMODE;
	}
	mbr1k_set_root(mbr1k, pnptr);
	return 0;
}

int silofs_mbi_sbaddr(const struct silofs_mbr_info *mbi,
                      struct silofs_uaddr *out_sb_uaddr)
{
	if (mbi_mode(mbi) != SILOFS_MBR_FS) {
		return -SILOFS_EMBRMODE;
	}
	mbr1k_sb_addr(&mbi->mb_mbr1k, out_sb_uaddr);
	return 0;
}

int silofs_mbi_set_sbaddr(struct silofs_mbr_info *mbi,
                          const struct silofs_uaddr *sb_uaddr)
{
	if (mbi_mode(mbi) != SILOFS_MBR_FS) {
		return -SILOFS_EMBRMODE;
	}
	mbr1k_set_sb_addr(&mbi->mb_mbr1k, sb_uaddr);
	return 0;
}

static void mbi_get_mbr1k(const struct silofs_mbr_info *mbi,
                          struct silofs_mbr1k *out_mbr1k)
{
	memcpy(out_mbr1k, &mbi->mb_mbr1k, sizeof(*out_mbr1k));
}

int silofs_mbi_export(const struct silofs_mbr_info *mbi,
                      struct silofs_mbref *out_mbref,
                      struct silofs_mbr1k *out_mbr1k_enc)
{
	struct silofs_mbr1k mbr1k;
	struct silofs_mbraux aux;
	int err;

	mbi_get_mbr1k(mbi, &mbr1k);
	err = mbraux_init(&aux, &mbi->mb_meta);
	if (err) {
		return err;
	}
	err = mbraux_encode_mbr1k(&aux, &mbr1k, out_mbr1k_enc);
	if (err) {
		goto out;
	}
	mbraux_calc_mbref(&aux, out_mbr1k_enc, out_mbref);
out:
	mbraux_fini(&aux);
	return err;
}

static int
mbi_set_mbr1k(struct silofs_mbr_info *mbi, const struct silofs_mbr1k *mbr1k)
{
	if (mbi_mode(mbi) != mbr1k_mode(mbr1k)) {
		return -SILOFS_EMBRMODE;
	}
	memcpy(&mbi->mb_mbr1k, mbr1k, sizeof(mbi->mb_mbr1k));
	return 0;
}

int silofs_mbi_import(struct silofs_mbr_info *mbi,
                      const struct silofs_mbref *mbref,
                      const struct silofs_mbr1k *mbr1k_enc)
{
	struct silofs_mbr1k mbr1k;
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, &mbi->mb_meta);
	if (err) {
		return err;
	}
	err = mbraux_verify_mbref(&aux, mbref, mbr1k_enc);
	if (err) {
		goto out;
	}
	err = mbraux_decode_mbr1k(&aux, mbr1k_enc, &mbr1k);
	if (err) {
		goto out;
	}
	err = mbi_set_mbr1k(mbi, &mbr1k);
out:
	mbraux_fini(&aux);
	return err;
}
