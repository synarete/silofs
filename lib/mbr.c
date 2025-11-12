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

static enum silofs_mbr_kind mbr1k_kind(const struct silofs_mbr1k *mbr1k)
{
	const uint32_t flavour = silofs_le32_to_cpu(mbr1k->mbr_kind);

	return (enum silofs_mbr_kind)flavour;
}

static void
mbr1k_set_kind(struct silofs_mbr1k *mbr1k, enum silofs_mbr_kind mbr_kind)
{
	mbr1k->mbr_kind = silofs_cpu_to_le32((uint32_t)mbr_kind);
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

static void
mbr1k_root(const struct silofs_mbr1k *mbr1k, struct silofs_paddr *out_paddr)
{
	silofs_paddr64b_xtoh(&mbr1k->mbr_root, out_paddr);
}

static void
mbr1k_set_root(struct silofs_mbr1k *mbr1k, const struct silofs_paddr *paddr)
{
	silofs_paddr64b_htox(&mbr1k->mbr_root, paddr);
}

static void mbr1k_reset_root(struct silofs_mbr1k *mbr1k)
{
	mbr1k_set_root(mbr1k, silofs_paddr_none());
}

static void mbr1k_setup(struct silofs_mbr1k *mbr1k)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_REVISION);
	mbr1k_set_kind(mbr1k, SILOFS_MBR_NONE);
	mbr1k_set_flags(mbr1k, 0);
	mbr1k_set_cipher(mbr1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                 SILOFS_CIPHER_MODE_DEFAULT);
	mbr1k_reset_root(mbr1k);
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
	mbr1k_main_ivkey(mbr1k, &mbr->main_ivkey);
	mbr1k_sb_addr(mbr1k, &mbr->sb_addr);
	mbr1k_root(mbr1k, &mbr->root);
	mbr->kind = mbr1k_kind(mbr1k);
	mbr->flags = mbr1k_flags(mbr1k);
	mbr->cipher_algo = (int32_t)mbr1k_chiper_algo(mbr1k);
	mbr->cipher_mode = (int32_t)mbr1k_chiper_mode(mbr1k);
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
	mbr1k_set_main_ivkey(mbr1k, &mbr->main_ivkey);
	mbr1k_set_cipher(mbr1k, mbr->cipher_algo, mbr->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mbr_init(struct silofs_mbr *mbr, enum silofs_mbr_kind flavour)
{
	silofs_memzero(mbr, sizeof(*mbr));
	silofs_paddr_reset(&mbr->root);
	silofs_uaddr_reset(&mbr->sb_addr);
	mbr->kind = flavour;
	mbr->flags = 0;
	mbr->cipher_algo = SILOFS_CIPHER_ALGO_DEFAULT;
	mbr->cipher_mode = SILOFS_CIPHER_MODE_DEFAULT;
}

static void mbr_fini(struct silofs_mbr *mbr)
{
	silofs_ivkey_reset(&mbr->main_ivkey);
	silofs_uaddr_reset(&mbr->sb_addr);
	silofs_paddr_reset(&mbr->root);
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
mbr_update_from(struct silofs_mbr *mbr, const struct silofs_mbr *other)
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

static void
mbr_root(const struct silofs_mbr *mbr, struct silofs_paddr *out_paddr)
{
	silofs_paddr_assign(out_paddr, &mbr->root);
}

static void
mbr_set_root(struct silofs_mbr *mbr, const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&mbr->root, paddr);
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

int silofs_mbrs_init(struct silofs_mbrs *mbrs)
{
	int err;

	mbr_init(&mbrs->fs_mbr, SILOFS_MBR_FS);
	mbr_init(&mbrs->ar_mbr, SILOFS_MBR_AR);
	silofs_ivkey_init(&mbrs->ivkey);

	err = silofs_cipher_init(&mbrs->cipher);
	if (err) {
		return err;
	}
	err = silofs_mdigest_init(&mbrs->mdigest);
	if (err) {
		silofs_cipher_fini(&mbrs->cipher);
		return err;
	}
	return 0;
}

void silofs_mbrs_fini(struct silofs_mbrs *mbrs)
{
	silofs_mdigest_fini(&mbrs->mdigest);
	silofs_cipher_fini(&mbrs->cipher);
	silofs_ivkey_reset(&mbrs->ivkey);
	mbr_fini(&mbrs->fs_mbr);
	mbr_fini(&mbrs->ar_mbr);
}

int silofs_mbrs_derive_ivkey(struct silofs_mbrs *mbrs,
                             const struct silofs_password *pw)
{
	const struct silofs_mdigest *md = &mbrs->mdigest;
	int ret = 0;

	silofs_ivkey_reset(&mbrs->ivkey);
	if ((pw != nullptr) && (pw->passlen > 0)) {
		ret = silofs_derive_default_ivkey(md, pw, &mbrs->ivkey);
	}
	return ret;
}

int silofs_mbrs_regen(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind)
{
	int ret;

	switch (mkind) {
	case SILOFS_MBR_FS:
		mbr_gen_uuid(&mbrs->fs_mbr);
		ret = mbr_gen_ivkey(&mbrs->fs_mbr, &mbrs->mdigest);
		break;
	case SILOFS_MBR_AR:
		mbr_gen_uuid(&mbrs->ar_mbr);
		ret = mbr_gen_ivkey(&mbrs->ar_mbr, &mbrs->mdigest);
		break;
	case SILOFS_MBR_NONE:
	default:
		ret = -SILOFS_EINVAL;
		break;
	}
	return ret;
}

void silofs_mbrs_update_sb_addr(struct silofs_mbrs *mbrs,
                                const struct silofs_uaddr *sb_uaddr)
{
	if (!mbr_has_sb_addr(&mbrs->fs_mbr, sb_uaddr)) {
		mbr_set_sb_addr(&mbrs->fs_mbr, sb_uaddr);
		mbr_gen_uuid(&mbrs->fs_mbr);
	}
}

int silofs_mbrs_root(const struct silofs_mbrs *mbrs,
                     enum silofs_mbr_kind mkind,
                     struct silofs_paddr *out_paddr)
{
	switch (mkind) {
	case SILOFS_MBR_FS:
		mbr_root(&mbrs->fs_mbr, out_paddr);
		break;
	case SILOFS_MBR_AR:
		mbr_root(&mbrs->ar_mbr, out_paddr);
		break;
	case SILOFS_MBR_NONE:
	default:
		return -SILOFS_EINVAL;
	}
	return silofs_paddr_isnull(out_paddr) ? -SILOFS_ENOENT : 0;
}

void silofs_mbrs_set_root(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind,
                          const struct silofs_paddr *paddr)
{
	switch (mkind) {
	case SILOFS_MBR_FS:
		mbr_set_root(&mbrs->fs_mbr, paddr);
		break;
	case SILOFS_MBR_AR:
		mbr_set_root(&mbrs->ar_mbr, paddr);
		break;
	case SILOFS_MBR_NONE:
	default:
		break;
	}
}

static void mbrs_calc_addr_of(const struct silofs_mbrs *mbrs,
                              const struct silofs_mbr1k *mbr1k,
                              struct silofs_paddr *out_paddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(mbr1k),
		.iov_len = sizeof(*mbr1k),
	};

	silofs_calc_cas_paddr(&mbrs->mdigest, SILOFS_MTYPE_MBR, &iov, 1,
	                      out_paddr);
}

static int mbrs_verify_mref(const struct silofs_mbrs *mbrs,
                            const struct silofs_paddr *mref,
                            const struct silofs_mbr1k *mbr1k)
{
	struct silofs_paddr paddr;

	mbrs_calc_addr_of(mbrs, mbr1k, &paddr);
	return silofs_paddr_isequal(mref, &paddr) ? 0 : -SILOFS_EBADMBR;
}

static int
mbrs_encode_fs(const struct silofs_mbrs *mbrs, struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(&mbrs->fs_mbr, &mbrs->mdigest, &mbrs->cipher,
	                  &mbrs->ivkey, out_mbr1k);
}

static int mbrs_encode_fs_mbr(const struct silofs_mbrs *mbrs,
                              struct silofs_paddr *out_mref,
                              struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbrs_encode_fs(mbrs, out_mbr1k);
	if (err) {
		log_err("failed to encode fs-mbr: err=%d", err);
		return err;
	}
	mbrs_calc_addr_of(mbrs, out_mbr1k, out_mref);
	return 0;
}

static int
mbrs_decode_fs(struct silofs_mbrs *mbrs, const struct silofs_mbr1k *mbr1k)
{
	return mbr_decode(&mbrs->fs_mbr, &mbrs->mdigest, &mbrs->cipher,
	                  &mbrs->ivkey, mbr1k);
}

static int
mbrs_decode_fs_mbr(struct silofs_mbrs *mbrs, const struct silofs_paddr *mref,
                   const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbrs_verify_mref(mbrs, mref, mbr1k);
	if (err) {
		return err;
	}
	err = mbrs_decode_fs(mbrs, mbr1k);
	if (err) {
		log_dbg("failed to decode fs-mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
mbrs_encode_ar(const struct silofs_mbrs *mbrs, struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(&mbrs->ar_mbr, &mbrs->mdigest, &mbrs->cipher,
	                  &mbrs->ivkey, out_mbr1k);
}

static int mbrs_encode_ar_mbr(const struct silofs_mbrs *mbrs,
                              struct silofs_paddr *out_mref,
                              struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbrs_encode_ar(mbrs, out_mbr1k);
	if (err) {
		log_err("failed to encode ar-mbr: err=%d", err);
		return err;
	}
	mbrs_calc_addr_of(mbrs, out_mbr1k, out_mref);
	return 0;
}

static int
mbrs_decode_ar(struct silofs_mbrs *mbrs, const struct silofs_mbr1k *mbr1k)
{
	return mbr_decode(&mbrs->ar_mbr, &mbrs->mdigest, &mbrs->cipher,
	                  &mbrs->ivkey, mbr1k);
}

static int
mbrs_decode_ar_mbr(struct silofs_mbrs *mbrs, const struct silofs_paddr *mref,
                   const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbrs_verify_mref(mbrs, mref, mbr1k);
	if (err) {
		return err;
	}
	err = mbrs_decode_ar(mbrs, mbr1k);
	if (err) {
		log_dbg("failed to decode ar-mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_mbrs_encode(const struct silofs_mbrs *mbrs,
                       enum silofs_mbr_kind mkind,
                       struct silofs_paddr *out_mref,
                       struct silofs_mbr1k *out_mbr1k)
{
	int err;

	switch (mkind) {
	case SILOFS_MBR_FS:
		err = mbrs_encode_fs_mbr(mbrs, out_mref, out_mbr1k);
		break;
	case SILOFS_MBR_AR:
		err = mbrs_encode_ar_mbr(mbrs, out_mref, out_mbr1k);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

int silofs_mbrs_decode(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind,
                       const struct silofs_paddr *mref,
                       const struct silofs_mbr1k *mbr1k)
{
	int err;

	switch (mkind) {
	case SILOFS_MBR_FS:
		err = mbrs_decode_fs_mbr(mbrs, mref, mbr1k);
		break;
	case SILOFS_MBR_AR:
		err = mbrs_decode_ar_mbr(mbrs, mref, mbr1k);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

static void mbrs_update_fs_mbr(struct silofs_mbrs *mbrs)
{
	mbr_update_from(&mbrs->fs_mbr, &mbrs->ar_mbr);
}

static void mbrs_update_ar_mbr(struct silofs_mbrs *mbrs)
{
	mbr_update_from(&mbrs->ar_mbr, &mbrs->fs_mbr);
}

int silofs_mbrs_update(struct silofs_mbrs *mbrs, enum silofs_mbr_kind mkind)
{
	int err = 0;

	switch (mkind) {
	case SILOFS_MBR_FS:
		mbrs_update_fs_mbr(mbrs);
		break;
	case SILOFS_MBR_AR:
		mbrs_update_ar_mbr(mbrs);
		break;
	case SILOFS_MBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}
