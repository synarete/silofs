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
#include "bs.h"
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

static enum silofs_mbr_flavour mbr1k_flavour(const struct silofs_mbr1k *mbr1k)
{
	const uint32_t flavour = silofs_le32_to_cpu(mbr1k->mbr_flavour);

	return (enum silofs_mbr_flavour)flavour;
}

static void
mbr1k_set_flavour(struct silofs_mbr1k *mbr1k, enum silofs_mbr_flavour flavour)
{
	mbr1k->mbr_flavour = silofs_cpu_to_le32((uint32_t)flavour);
}

static int32_t mbr1k_chiper_algo(const struct silofs_mbr1k *mbr1k)
{
	return (int32_t)silofs_le32_to_cpu(mbr1k->mbr_chiper_algo);
}

static int32_t mbr1k_chiper_mode(const struct silofs_mbr1k *mbr1k)
{
	return (int32_t)silofs_le32_to_cpu(mbr1k->mbr_chiper_mode);
}

static void mbr1k_set_cipher(struct silofs_mbr1k *mbr1k, int32_t cipher_algo,
                             int32_t cipher_mode)
{
	mbr1k->mbr_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	mbr1k->mbr_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

static void mbr1k_setup(struct silofs_mbr1k *mbr1k)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_VERSION);
	mbr1k_set_flavour(mbr1k, SILOFS_MBR_NONE);
	mbr1k_set_flags(mbr1k, 0);
	mbr1k_set_cipher(mbr1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                 SILOFS_CIPHER_MODE_DEFAULT);
}

static void mbr1k_sb_addr(const struct silofs_mbr1k *mbr1k,
                          struct silofs_uaddr *out_sb_addr)
{
	silofs_uaddr96b_xtoh(&mbr1k->mbr_sb_addr, out_sb_addr);
}

static void mbr1k_set_sb_addr(struct silofs_mbr1k *mbr1k,
                              const struct silofs_uaddr *sb_addr)
{
	silofs_uaddr96b_htox(&mbr1k->mbr_sb_addr, sb_addr);
}

static void mbr1k_arix_addr(const struct silofs_mbr1k *mbr1k,
                            struct silofs_caddr *out_arix_addr)
{
	silofs_caddr64b_xtoh(&mbr1k->mbr_arix_addr, out_arix_addr);
}

static void mbr1k_set_arix_addr(struct silofs_mbr1k *mbr1k,
                                const struct silofs_caddr *arix_addr)
{
	silofs_caddr64b_htox(&mbr1k->mbr_arix_addr, arix_addr);
}

static void mbr1k_main_ivkey(const struct silofs_mbr1k *mbr1k,
                             struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &mbr1k->mbr_main_key,
	                   &mbr1k->mbr_main_iv);
}

static void mbr1k_set_main_ivkey(struct silofs_mbr1k *mbr1k,
                                 const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&mbr1k->mbr_main_key, &ivkey->key);
	silofs_iv_assign(&mbr1k->mbr_main_iv, &ivkey->iv);
}

static int mbr1k_check_base(const struct silofs_mbr1k *mbr1k)
{
	const uint64_t magic = mbr1k_magic(mbr1k);
	const uint64_t version = mbr1k_version(mbr1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_MBR_MAGIC) && (version != SILOFS_FMT_VERSION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad mbr magic: 0x%lx", magic);
		return -SILOFS_EBADMBR;
	}
	if (version != SILOFS_FMT_VERSION) {
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

static int mbr1k_check(const struct silofs_mbr1k *mbr1k)
{
	int algo;
	int mode;
	int err;

	err = mbr1k_check_base(mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_check_uaddr_sb(mbr1k);
	if (err) {
		return err;
	}
	algo = mbr1k_chiper_algo(mbr1k);
	mode = mbr1k_chiper_mode(mbr1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static void
mbr1k_hash(const struct silofs_mbr1k *mbr1k, struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &mbr1k->mbr_hash);
}

static void
mbr1k_set_hash(struct silofs_mbr1k *mbr1k, const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&mbr1k->mbr_hash, hash);
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
	mbr1k_main_ivkey(mbr1k, &mbr->main_ivkey);
	mbr1k_sb_addr(mbr1k, &mbr->sb_addr);
	mbr1k_arix_addr(mbr1k, &mbr->arix_addr);
	mbr->flavour = mbr1k_flavour(mbr1k);
	mbr->flags = mbr1k_flags(mbr1k);
	mbr->cipher_algo = (int32_t)mbr1k_chiper_algo(mbr1k);
	mbr->cipher_mode = (int32_t)mbr1k_chiper_mode(mbr1k);
}

static void
mbr1k_htox(struct silofs_mbr1k *mbr1k, const struct silofs_mbr *mbr)
{
	mbr1k_setup(mbr1k);
	mbr1k_set_sb_addr(mbr1k, &mbr->sb_addr);
	mbr1k_set_arix_addr(mbr1k, &mbr->arix_addr);
	mbr1k_set_flavour(mbr1k, mbr->flavour);
	mbr1k_set_flags(mbr1k, mbr->flags);
	mbr1k_set_uuid(mbr1k, &mbr->uuid);
	mbr1k_set_main_ivkey(mbr1k, &mbr->main_ivkey);
	mbr1k_set_cipher(mbr1k, mbr->cipher_algo, mbr->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mbr_init(struct silofs_mbr *mbr, enum silofs_mbr_flavour flavour)
{
	silofs_memzero(mbr, sizeof(*mbr));
	silofs_uaddr_reset(&mbr->sb_addr);
	silofs_caddr_reset(&mbr->arix_addr);
	mbr->flavour = flavour;
	mbr->flags = 0;
	mbr->cipher_algo = SILOFS_CIPHER_AES256;
	mbr->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

static void mbr_fini(struct silofs_mbr *mbr)
{
	silofs_ivkey_reset(&mbr->main_ivkey);
	silofs_uaddr_reset(&mbr->sb_addr);
	silofs_caddr_reset(&mbr->arix_addr);
}

static void mbr_gen_uuid(struct silofs_mbr *mbr)
{
	silofs_uuid_generate(&mbr->uuid);
}

static void
mbr_set_ivkey(struct silofs_mbr *mbr, const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&mbr->main_ivkey, ivkey);
}

static void
mbr_sync_with(struct silofs_mbr *mbr, const struct silofs_mbr *other)
{
	mbr_set_ivkey(mbr, &other->main_ivkey);
	mbr->cipher_algo = other->cipher_algo;
	mbr->cipher_mode = other->cipher_mode;
}

/*
 * Try to add some pseudo-randomness for the rare (yet, possible) case where
 * '/dev/urandom' does not provide good-enough random  bits stream.
 */
static int
ivkey_make_prand(struct silofs_ivkey *ivkey, const struct silofs_mdigest *md)
{
	struct silofs_password pw = { .passlen = 0 };

	silofs_password_mkrand(&pw);
	return silofs_derive_default_ivkey(md, &pw, ivkey);
}

static int
mbr_gen_ivkey(struct silofs_mbr *mbr, const struct silofs_mdigest *md)
{
	struct silofs_ivkey ivkey[2];
	int err;

	silofs_ivkey_mkrand(&ivkey[0]);
	err = ivkey_make_prand(&ivkey[1], md);
	if (err) {
		log_dbg("failed to make prandom ivkey: err=%d", err);
		return err;
	}
	silofs_ivkey_xor_with(&ivkey[0], &ivkey[1]);
	mbr_set_ivkey(mbr, &ivkey[0]);
	return 0;
}

static void
mbr_set_sb_addr(struct silofs_mbr *mbr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&mbr->sb_addr, uaddr);
	mbr_gen_uuid(mbr);
}

static void
mbr_set_arix_addr(struct silofs_mbr *mbr, const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&mbr->arix_addr, caddr);
}

void silofs_make_mbr_uaddr(const struct silofs_blobid *blobid,
                           struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const enum silofs_mtype mtype = SILOFS_MTYPE_MBR;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsid_setup(&lsid, blobid, 0, mtype, height, mtype);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
encrypt_mbr1k(const struct silofs_cipher *ci, const struct silofs_ivkey *ivkey,
              const struct silofs_mbr1k *mbr1k_in,
              struct silofs_mbr1k *mbr1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, mbr1k_in, mbr1k_out,
	                          sizeof(*mbr1k_out));
}

static int
decrypt_mbr1k(const struct silofs_cipher *ci, const struct silofs_ivkey *ivkey,
              const struct silofs_mbr1k *mbr1k_in,
              struct silofs_mbr1k *mbr1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, mbr1k_in, mbr1k_out,
	                          sizeof(*mbr1k_out));
}

static int mbr_encode(const struct silofs_mbr *mbr,     //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_ivkey *ivkey, //
                      struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbr1k mbr1k;

	mbr1k_htox(&mbr1k, mbr);
	mbr1k_stamp(&mbr1k, mdigest);
	return encrypt_mbr1k(cipher, ivkey, &mbr1k, out_mbr1k);
}

static int mbr_decode(struct silofs_mbr *mbr, //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_ivkey *ivkey,
                      const struct silofs_mbr1k *enc_mbr1k)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 1 };
	int err;

	err = decrypt_mbr1k(cipher, ivkey, enc_mbr1k, &mbr1k);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mbri_init(struct silofs_mbrinfo *mbri)
{
	int err;

	mbr_init(&mbri->fs_mbr, SILOFS_MBR_FS);
	mbr_init(&mbri->ar_mbr, SILOFS_MBR_AR);
	silofs_ivkey_init(&mbri->ivkey);

	err = silofs_cipher_init(&mbri->cipher);
	if (err) {
		return err;
	}
	err = silofs_mdigest_init(&mbri->mdigest);
	if (err) {
		silofs_cipher_fini(&mbri->cipher);
		return err;
	}
	return 0;
}

void silofs_mbri_fini(struct silofs_mbrinfo *mbri)
{
	silofs_mdigest_fini(&mbri->mdigest);
	silofs_cipher_fini(&mbri->cipher);
	silofs_ivkey_reset(&mbri->ivkey);
	mbr_fini(&mbri->fs_mbr);
	mbr_fini(&mbri->ar_mbr);
}

int silofs_mbri_derive_ivkey(struct silofs_mbrinfo *mbri,
                             const struct silofs_password *pw)
{
	int ret = 0;

	if ((pw != nullptr) && (pw->passlen > 0)) {
		ret = silofs_derive_default_ivkey(&mbri->mdigest, pw,
		                                  &mbri->ivkey);
	} else {
		silofs_ivkey_reset(&mbri->ivkey);
	}
	return ret;
}

int silofs_mbri_regenerate_fs_mbr(struct silofs_mbrinfo *mbri)
{
	mbr_gen_uuid(&mbri->fs_mbr);
	return mbr_gen_ivkey(&mbri->fs_mbr, &mbri->mdigest);
}

void silofs_mbri_update_sb_addr(struct silofs_mbrinfo *mbri,
                                const struct silofs_uaddr *sb_uaddr)
{
	mbr_set_sb_addr(&mbri->fs_mbr, sb_uaddr);
}

void silofs_mbri_update_arix_addr(struct silofs_mbrinfo *mbri,
                                  const struct silofs_caddr *arix_caddr)
{
	mbr_set_arix_addr(&mbri->ar_mbr, arix_caddr);
}

static void mbri_calc_addr_of(const struct silofs_mbrinfo *mbri,
                              const struct silofs_mbr1k *mbr1k,
                              struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(mbr1k),
		.iov_len = sizeof(*mbr1k),
	};
	const enum silofs_ctype ctype = SILOFS_CTYPE_MBR;

	silofs_calc_caddr_of(&mbri->mdigest, &iov, 1, ctype, out_caddr);
}

static int mbri_verify_mref(const struct silofs_mbrinfo *mbri,
                            const struct silofs_caddr *mref,
                            const struct silofs_mbr1k *mbr1k)
{
	struct silofs_caddr caddr = {
		.ctype = SILOFS_CTYPE_NONE,
	};

	mbri_calc_addr_of(mbri, mbr1k, &caddr);
	return silofs_caddr_isequal(mref, &caddr) ? 0 : -SILOFS_EBADMBR;
}

static int mbri_encode_fs(const struct silofs_mbrinfo *mbri,
                          struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(&mbri->fs_mbr, &mbri->mdigest, &mbri->cipher,
	                  &mbri->ivkey, out_mbr1k);
}

static int mbri_encode_fs_mbr(const struct silofs_mbrinfo *mbri,
                              struct silofs_caddr *out_mref,
                              struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbri_encode_fs(mbri, out_mbr1k);
	if (err) {
		log_err("failed to encode fs-mbr: err=%d", err);
		return err;
	}
	mbri_calc_addr_of(mbri, out_mbr1k, out_mref);
	return 0;
}

static int
mbri_decode_fs(struct silofs_mbrinfo *mbri, const struct silofs_mbr1k *mbr1k)
{
	return mbr_decode(&mbri->fs_mbr, &mbri->mdigest, &mbri->cipher,
	                  &mbri->ivkey, mbr1k);
}

static int mbri_decode_fs_mbr(struct silofs_mbrinfo *mbri,
                              const struct silofs_caddr *mref,
                              const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbri_verify_mref(mbri, mref, mbr1k);
	if (err) {
		return err;
	}
	err = mbri_decode_fs(mbri, mbr1k);
	if (err) {
		log_dbg("failed to decode fs-mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int mbri_encode_ar(const struct silofs_mbrinfo *mbri,
                          struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(&mbri->ar_mbr, &mbri->mdigest, &mbri->cipher,
	                  &mbri->ivkey, out_mbr1k);
}

static int mbri_encode_ar_mbr(const struct silofs_mbrinfo *mbri,
                              struct silofs_caddr *out_mref,
                              struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbri_encode_ar(mbri, out_mbr1k);
	if (err) {
		log_err("failed to encode ar-mbr: err=%d", err);
		return err;
	}
	mbri_calc_addr_of(mbri, out_mbr1k, out_mref);
	return 0;
}

static int
mbri_decode_ar(struct silofs_mbrinfo *mbri, const struct silofs_mbr1k *mbr1k)
{
	return mbr_decode(&mbri->ar_mbr, &mbri->mdigest, &mbri->cipher,
	                  &mbri->ivkey, mbr1k);
}

static int mbri_decode_ar_mbr(struct silofs_mbrinfo *mbri,
                              const struct silofs_caddr *mref,
                              const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbri_verify_mref(mbri, mref, mbr1k);
	if (err) {
		return err;
	}
	err = mbri_decode_ar(mbri, mbr1k);
	if (err) {
		log_dbg("failed to decode ar-mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_mbri_encode_mbr(const struct silofs_mbrinfo *mbri,
                           enum silofs_mbr_flavour flavour,
                           struct silofs_caddr *out_mref,
                           struct silofs_mbr1k *out_mbr1k)
{
	int err;

	switch (flavour) {
	case SILOFS_MBR_FS:
		err = mbri_encode_fs_mbr(mbri, out_mref, out_mbr1k);
		break;
	case SILOFS_MBR_AR:
		err = mbri_encode_ar_mbr(mbri, out_mref, out_mbr1k);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

int silofs_mbri_decode_mbr(struct silofs_mbrinfo *mbri,
                           enum silofs_mbr_flavour flavour,
                           const struct silofs_caddr *mref,
                           const struct silofs_mbr1k *mbr1k)
{
	int err;

	switch (flavour) {
	case SILOFS_MBR_FS:
		err = mbri_decode_fs_mbr(mbri, mref, mbr1k);
		break;
	case SILOFS_MBR_AR:
		err = mbri_decode_ar_mbr(mbri, mref, mbr1k);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

static void mbri_sync_fs_mbr(struct silofs_mbrinfo *mbri)
{
	mbr_sync_with(&mbri->fs_mbr, &mbri->ar_mbr);
}

static void mbri_sync_ar_mbr(struct silofs_mbrinfo *mbri)
{
	mbr_sync_with(&mbri->ar_mbr, &mbri->fs_mbr);
}

int silofs_mbri_sync_mbrs(struct silofs_mbrinfo *mbri,
                          enum silofs_mbr_flavour dst_flavour)
{
	int err = 0;

	switch (dst_flavour) {
	case SILOFS_MBR_FS:
		mbri_sync_fs_mbr(mbri);
		break;
	case SILOFS_MBR_AR:
		mbri_sync_ar_mbr(mbri);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}
