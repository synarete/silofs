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
#include "ubs.h"
#include "gbr.h"
#include "vfs.h"
#include "env.h"

static uint64_t gbr1k_magic(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le64_to_cpu(gbr1k->gbr_magic);
}

static void gbr1k_set_magic(struct silofs_gbr1k *gbr1k, uint64_t magic)
{
	gbr1k->gbr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t gbr1k_version(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le64_to_cpu(gbr1k->gbr_version);
}

static void gbr1k_set_version(struct silofs_gbr1k *gbr1k, uint64_t version)
{
	gbr1k->gbr_version = silofs_cpu_to_le64(version);
}

static uint32_t gbr1k_flags(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le32_to_cpu(gbr1k->gbr_flags);
}

static void gbr1k_set_flags(struct silofs_gbr1k *gbr1k, uint32_t flags)
{
	gbr1k->gbr_flags = silofs_cpu_to_le32(flags);
}

static enum silofs_gbr_kind gbr1k_kind(const struct silofs_gbr1k *gbr1k)
{
	const uint32_t gbr_kind = silofs_le32_to_cpu(gbr1k->gbr_kind);

	return (enum silofs_gbr_kind)gbr_kind;
}

static void
gbr1k_set_kind(struct silofs_gbr1k *gbr1k, enum silofs_gbr_kind gbr_kind)
{
	gbr1k->gbr_kind = silofs_cpu_to_le32((uint32_t)gbr_kind);
}

static int32_t gbr1k_chiper_algo(const struct silofs_gbr1k *gbr1k)
{
	return (int32_t)silofs_le32_to_cpu(gbr1k->gbr_chiper_algo);
}

static int32_t gbr1k_chiper_mode(const struct silofs_gbr1k *gbr1k)
{
	return (int32_t)silofs_le32_to_cpu(gbr1k->gbr_chiper_mode);
}

static void gbr1k_set_cipher(struct silofs_gbr1k *gbr1k, int32_t cipher_algo,
                             int32_t cipher_mode)
{
	gbr1k->gbr_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	gbr1k->gbr_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

static void gbr1k_sb_addr(const struct silofs_gbr1k *gbr1k,
                          struct silofs_uaddr *out_sb_addr)
{
	silofs_uaddr128b_xtoh(&gbr1k->gbr_sb_addr, out_sb_addr);
}

static void gbr1k_set_sb_addr(struct silofs_gbr1k *gbr1k,
                              const struct silofs_uaddr *sb_addr)
{
	silofs_uaddr128b_htox(&gbr1k->gbr_sb_addr, sb_addr);
}

static void
gbr1k_root(const struct silofs_gbr1k *gbr1k, struct silofs_paddr *out_paddr)
{
	silofs_paddr64b_xtoh(&gbr1k->gbr_root, out_paddr);
}

static void
gbr1k_set_root(struct silofs_gbr1k *gbr1k, const struct silofs_paddr *paddr)
{
	silofs_paddr64b_htox(&gbr1k->gbr_root, paddr);
}

static void gbr1k_reset_root(struct silofs_gbr1k *gbr1k)
{
	gbr1k_set_root(gbr1k, silofs_paddr_none());
}

static void gbr1k_setup(struct silofs_gbr1k *gbr1k)
{
	silofs_memzero(gbr1k, sizeof(*gbr1k));
	gbr1k_set_magic(gbr1k, SILOFS_MBR_MAGIC);
	gbr1k_set_version(gbr1k, SILOFS_FMT_REVISION);
	gbr1k_set_kind(gbr1k, SILOFS_GBR_NONE);
	gbr1k_set_flags(gbr1k, 0);
	gbr1k_set_cipher(gbr1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                 SILOFS_CIPHER_MODE_DEFAULT);
	gbr1k_reset_root(gbr1k);
}

static void gbr1k_main_ivkey(const struct silofs_gbr1k *gbr1k,
                             struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &gbr1k->gbr_main_key,
	                   &gbr1k->gbr_main_iv);
}

static void gbr1k_set_main_ivkey(struct silofs_gbr1k *gbr1k,
                                 const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&gbr1k->gbr_main_key, &ivkey->key);
	silofs_iv_assign(&gbr1k->gbr_main_iv, &ivkey->iv);
}

static int gbr1k_check_base(const struct silofs_gbr1k *gbr1k)
{
	const uint64_t magic = gbr1k_magic(gbr1k);
	const uint64_t version = gbr1k_version(gbr1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_MBR_MAGIC) && (version != SILOFS_FMT_REVISION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad gbr magic: 0x%lx", magic);
		return -SILOFS_EBADMBR;
	}
	if (version != SILOFS_FMT_REVISION) {
		log_dbg("bad gbr version: %lu", version);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int gbr1k_check_uaddr_sb(const struct silofs_gbr1k *gbr1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_mtype mtype;

	gbr1k_sb_addr(gbr1k, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	height = silofs_uaddr_height(&uaddr);
	mtype = silofs_uaddr_mtype(&uaddr);
	if ((mtype != SILOFS_MTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad gbr uaddr-sb: voff=%ld mtype=%d height=%d",
		        uaddr.voff, (int)mtype, (int)height);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static void
gbr1k_uuid(const struct silofs_gbr1k *gbr1k, struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &gbr1k->gbr_uuid);
}

static void
gbr1k_set_uuid(struct silofs_gbr1k *gbr1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&gbr1k->gbr_uuid, uuid);
}

static int gbr1k_check(const struct silofs_gbr1k *gbr1k)
{
	int algo;
	int mode;
	int err;

	err = gbr1k_check_base(gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_check_uaddr_sb(gbr1k);
	if (err) {
		return err;
	}
	algo = gbr1k_chiper_algo(gbr1k);
	mode = gbr1k_chiper_mode(gbr1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static void
gbr1k_hash(const struct silofs_gbr1k *gbr1k, struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(&gbr1k->gbr_hash, hash);
}

static void
gbr1k_set_hash(struct silofs_gbr1k *gbr1k, const struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(hash, &gbr1k->gbr_hash);
}

static void gbr1k_calc_hash(const struct silofs_gbr1k *gbr1k,
                            const struct silofs_mdigest *md,
                            struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_gbr1k, gbr_hash);

	silofs_sha3_256_of(md, gbr1k, len, out_hash);
}

static void
gbr1k_stamp(struct silofs_gbr1k *gbr1k, const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	gbr1k_calc_hash(gbr1k, md, &hash);
	gbr1k_set_hash(gbr1k, &hash);
}

static int gbr1k_check_hash(const struct silofs_gbr1k *gbr1k,
                            const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	gbr1k_hash(gbr1k, &hash[0]);
	gbr1k_calc_hash(gbr1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int
gbr1k_verify(const struct silofs_gbr1k *gbr1k, const struct silofs_mdigest *md)
{
	int err;

	err = gbr1k_check(gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_check_hash(gbr1k, md);
	if (err) {
		return err;
	}
	return 0;
}

static void
gbr1k_xtoh(const struct silofs_gbr1k *gbr1k, struct silofs_gbr *gbr)
{
	gbr1k_uuid(gbr1k, &gbr->uuid);
	gbr1k_main_ivkey(gbr1k, &gbr->main_ivkey);
	gbr1k_sb_addr(gbr1k, &gbr->sb_addr);
	gbr1k_root(gbr1k, &gbr->root);
	gbr->kind = gbr1k_kind(gbr1k);
	gbr->flags = gbr1k_flags(gbr1k);
	gbr->cipher_algo = (int32_t)gbr1k_chiper_algo(gbr1k);
	gbr->cipher_mode = (int32_t)gbr1k_chiper_mode(gbr1k);
}

static void
gbr1k_htox(struct silofs_gbr1k *gbr1k, const struct silofs_gbr *gbr)
{
	gbr1k_setup(gbr1k);
	gbr1k_set_sb_addr(gbr1k, &gbr->sb_addr);
	gbr1k_set_root(gbr1k, &gbr->root);
	gbr1k_set_kind(gbr1k, gbr->kind);
	gbr1k_set_flags(gbr1k, gbr->flags);
	gbr1k_set_uuid(gbr1k, &gbr->uuid);
	gbr1k_set_main_ivkey(gbr1k, &gbr->main_ivkey);
	gbr1k_set_cipher(gbr1k, gbr->cipher_algo, gbr->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void gbr_init(struct silofs_gbr *gbr, enum silofs_gbr_kind flavour)
{
	silofs_memzero(gbr, sizeof(*gbr));
	silofs_paddr_reset(&gbr->root);
	silofs_uaddr_reset(&gbr->sb_addr);
	gbr->kind = flavour;
	gbr->flags = 0;
	gbr->cipher_algo = SILOFS_CIPHER_ALGO_DEFAULT;
	gbr->cipher_mode = SILOFS_CIPHER_MODE_DEFAULT;
}

static void gbr_fini(struct silofs_gbr *gbr)
{
	silofs_ivkey_reset(&gbr->main_ivkey);
	silofs_uaddr_reset(&gbr->sb_addr);
	silofs_paddr_reset(&gbr->root);
}

static void gbr_gen_uuid(struct silofs_gbr *gbr)
{
	silofs_uuid_generate(&gbr->uuid);
}

static void
gbr_set_ivkey(struct silofs_gbr *gbr, const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&gbr->main_ivkey, ivkey);
}

static void
gbr_update_from(struct silofs_gbr *gbr, const struct silofs_gbr *other)
{
	gbr_set_ivkey(gbr, &other->main_ivkey);
	gbr->cipher_algo = other->cipher_algo;
	gbr->cipher_mode = other->cipher_mode;
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
gbr_gen_ivkey(struct silofs_gbr *gbr, const struct silofs_mdigest *md)
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
	gbr_set_ivkey(gbr, &ivkey[0]);
	return 0;
}

static bool
gbr_has_sb_addr(const struct silofs_gbr *gbr, const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_isequal(&gbr->sb_addr, uaddr);
}

static void
gbr_set_sb_addr(struct silofs_gbr *gbr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&gbr->sb_addr, uaddr);
}

static void
gbr_root(const struct silofs_gbr *gbr, struct silofs_paddr *out_paddr)
{
	silofs_paddr_assign(out_paddr, &gbr->root);
}

static void
gbr_set_root(struct silofs_gbr *gbr, const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&gbr->root, paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
encrypt_gbr1k(const struct silofs_cipher *ci, const struct silofs_ivkey *ivkey,
              const struct silofs_gbr1k *gbr1k_in,
              struct silofs_gbr1k *gbr1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, gbr1k_in, gbr1k_out,
	                          sizeof(*gbr1k_out));
}

static int
decrypt_gbr1k(const struct silofs_cipher *ci, const struct silofs_ivkey *ivkey,
              const struct silofs_gbr1k *gbr1k_in,
              struct silofs_gbr1k *gbr1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, gbr1k_in, gbr1k_out,
	                          sizeof(*gbr1k_out));
}

static int gbr_encode(const struct silofs_gbr *gbr,     //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_ivkey *ivkey, //
                      struct silofs_gbr1k *out_gbr1k)
{
	struct silofs_gbr1k gbr1k;

	gbr1k_htox(&gbr1k, gbr);
	gbr1k_stamp(&gbr1k, mdigest);
	return encrypt_gbr1k(cipher, ivkey, &gbr1k, out_gbr1k);
}

static int gbr_decode(struct silofs_gbr *gbr, //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_ivkey *ivkey,
                      const struct silofs_gbr1k *enc_gbr1k)
{
	struct silofs_gbr1k gbr1k = { .gbr_magic = 1 };
	int err;

	err = decrypt_gbr1k(cipher, ivkey, enc_gbr1k, &gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_verify(&gbr1k, mdigest);
	if (err) {
		return err;
	}
	gbr1k_xtoh(&gbr1k, gbr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_gbrs_init(struct silofs_gbrs *gbrs)
{
	int err;

	gbr_init(&gbrs->fs_gbr, SILOFS_GBR_FS);
	gbr_init(&gbrs->ar_gbr, SILOFS_GBR_AR);
	silofs_ivkey_init(&gbrs->ivkey);

	err = silofs_cipher_init(&gbrs->cipher);
	if (err) {
		return err;
	}
	err = silofs_mdigest_init(&gbrs->mdigest);
	if (err) {
		silofs_cipher_fini(&gbrs->cipher);
		return err;
	}
	return 0;
}

void silofs_gbrs_fini(struct silofs_gbrs *gbrs)
{
	silofs_mdigest_fini(&gbrs->mdigest);
	silofs_cipher_fini(&gbrs->cipher);
	silofs_ivkey_reset(&gbrs->ivkey);
	gbr_fini(&gbrs->fs_gbr);
	gbr_fini(&gbrs->ar_gbr);
}

int silofs_gbrs_derive_ivkey(struct silofs_gbrs *gbrs,
                             const struct silofs_password *pw)
{
	const struct silofs_mdigest *md = &gbrs->mdigest;
	int ret = 0;

	silofs_ivkey_reset(&gbrs->ivkey);
	if ((pw != nullptr) && (pw->passlen > 0)) {
		ret = silofs_derive_default_ivkey(md, pw, &gbrs->ivkey);
	}
	return ret;
}

int silofs_gbrs_regen(struct silofs_gbrs *gbrs, enum silofs_gbr_kind gdr_kind)
{
	int ret;

	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		gbr_gen_uuid(&gbrs->fs_gbr);
		ret = gbr_gen_ivkey(&gbrs->fs_gbr, &gbrs->mdigest);
		break;
	case SILOFS_GBR_AR:
		gbr_gen_uuid(&gbrs->ar_gbr);
		ret = gbr_gen_ivkey(&gbrs->ar_gbr, &gbrs->mdigest);
		break;
	case SILOFS_GBR_NONE:
	default:
		ret = -SILOFS_EINVAL;
		break;
	}
	return ret;
}

void silofs_gbrs_update_sb_addr(struct silofs_gbrs *gbrs,
                                const struct silofs_uaddr *sb_uaddr)
{
	if (!gbr_has_sb_addr(&gbrs->fs_gbr, sb_uaddr)) {
		gbr_set_sb_addr(&gbrs->fs_gbr, sb_uaddr);
		gbr_gen_uuid(&gbrs->fs_gbr);
	}
}

int silofs_gbrs_root(const struct silofs_gbrs *gbrs,
                     enum silofs_gbr_kind gdr_kind,
                     struct silofs_paddr *out_paddr)
{
	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		gbr_root(&gbrs->fs_gbr, out_paddr);
		break;
	case SILOFS_GBR_AR:
		gbr_root(&gbrs->ar_gbr, out_paddr);
		break;
	case SILOFS_GBR_NONE:
	default:
		return -SILOFS_EINVAL;
	}
	return silofs_paddr_isnull(out_paddr) ? -SILOFS_ENOENT : 0;
}

void silofs_gbrs_set_root(struct silofs_gbrs *gbrs,
                          enum silofs_gbr_kind gdr_kind,
                          const struct silofs_paddr *paddr)
{
	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		gbr_set_root(&gbrs->fs_gbr, paddr);
		break;
	case SILOFS_GBR_AR:
		gbr_set_root(&gbrs->ar_gbr, paddr);
		break;
	case SILOFS_GBR_NONE:
	default:
		break;
	}
}

static void gbrs_calc_addr_of(const struct silofs_gbrs *gbrs,
                              const struct silofs_gbr1k *gbr1k,
                              struct silofs_paddr *out_paddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(gbr1k),
		.iov_len = sizeof(*gbr1k),
	};

	silofs_calc_cas_paddr(&gbrs->mdigest, SILOFS_MTYPE_GBR, &iov, 1,
	                      out_paddr);
}

static int gbrs_verify_mref(const struct silofs_gbrs *gbrs,
                            const struct silofs_paddr *mref,
                            const struct silofs_gbr1k *gbr1k)
{
	struct silofs_paddr paddr;

	gbrs_calc_addr_of(gbrs, gbr1k, &paddr);
	return silofs_paddr_isequal(mref, &paddr) ? 0 : -SILOFS_EBADMBR;
}

static int
gbrs_encode_fs(const struct silofs_gbrs *gbrs, struct silofs_gbr1k *out_gbr1k)
{
	return gbr_encode(&gbrs->fs_gbr, &gbrs->mdigest, &gbrs->cipher,
	                  &gbrs->ivkey, out_gbr1k);
}

static int gbrs_encode_fs_gbr(const struct silofs_gbrs *gbrs,
                              struct silofs_paddr *out_mref,
                              struct silofs_gbr1k *out_gbr1k)
{
	int err;

	err = gbrs_encode_fs(gbrs, out_gbr1k);
	if (err) {
		log_err("failed to encode fs-gbr: err=%d", err);
		return err;
	}
	gbrs_calc_addr_of(gbrs, out_gbr1k, out_mref);
	return 0;
}

static int
gbrs_decode_fs(struct silofs_gbrs *gbrs, const struct silofs_gbr1k *gbr1k)
{
	return gbr_decode(&gbrs->fs_gbr, &gbrs->mdigest, &gbrs->cipher,
	                  &gbrs->ivkey, gbr1k);
}

static int
gbrs_decode_fs_gbr(struct silofs_gbrs *gbrs, const struct silofs_paddr *mref,
                   const struct silofs_gbr1k *gbr1k)
{
	int err;

	err = gbrs_verify_mref(gbrs, mref, gbr1k);
	if (err) {
		return err;
	}
	err = gbrs_decode_fs(gbrs, gbr1k);
	if (err) {
		log_dbg("failed to decode fs-gbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
gbrs_encode_ar(const struct silofs_gbrs *gbrs, struct silofs_gbr1k *out_gbr1k)
{
	return gbr_encode(&gbrs->ar_gbr, &gbrs->mdigest, &gbrs->cipher,
	                  &gbrs->ivkey, out_gbr1k);
}

static int gbrs_encode_ar_gbr(const struct silofs_gbrs *gbrs,
                              struct silofs_paddr *out_mref,
                              struct silofs_gbr1k *out_gbr1k)
{
	int err;

	err = gbrs_encode_ar(gbrs, out_gbr1k);
	if (err) {
		log_err("failed to encode ar-gbr: err=%d", err);
		return err;
	}
	gbrs_calc_addr_of(gbrs, out_gbr1k, out_mref);
	return 0;
}

static int
gbrs_decode_ar(struct silofs_gbrs *gbrs, const struct silofs_gbr1k *gbr1k)
{
	return gbr_decode(&gbrs->ar_gbr, &gbrs->mdigest, &gbrs->cipher,
	                  &gbrs->ivkey, gbr1k);
}

static int
gbrs_decode_ar_gbr(struct silofs_gbrs *gbrs, const struct silofs_paddr *mref,
                   const struct silofs_gbr1k *gbr1k)
{
	int err;

	err = gbrs_verify_mref(gbrs, mref, gbr1k);
	if (err) {
		return err;
	}
	err = gbrs_decode_ar(gbrs, gbr1k);
	if (err) {
		log_dbg("failed to decode ar-gbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_gbrs_encode(const struct silofs_gbrs *gbrs,
                       enum silofs_gbr_kind gdr_kind,
                       struct silofs_paddr *out_mref,
                       struct silofs_gbr1k *out_gbr1k)
{
	int err;

	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		err = gbrs_encode_fs_gbr(gbrs, out_mref, out_gbr1k);
		break;
	case SILOFS_GBR_AR:
		err = gbrs_encode_ar_gbr(gbrs, out_mref, out_gbr1k);
		break;
	case SILOFS_GBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

int silofs_gbrs_decode(struct silofs_gbrs *gbrs, enum silofs_gbr_kind gdr_kind,
                       const struct silofs_paddr *mref,
                       const struct silofs_gbr1k *gbr1k)
{
	int err;

	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		err = gbrs_decode_fs_gbr(gbrs, mref, gbr1k);
		break;
	case SILOFS_GBR_AR:
		err = gbrs_decode_ar_gbr(gbrs, mref, gbr1k);
		break;
	case SILOFS_GBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

static void gbrs_update_fs_gbr(struct silofs_gbrs *gbrs)
{
	gbr_update_from(&gbrs->fs_gbr, &gbrs->ar_gbr);
}

static void gbrs_update_ar_gbr(struct silofs_gbrs *gbrs)
{
	gbr_update_from(&gbrs->ar_gbr, &gbrs->fs_gbr);
}

int silofs_gbrs_update(struct silofs_gbrs *gbrs, enum silofs_gbr_kind gdr_kind)
{
	int err = 0;

	switch (gdr_kind) {
	case SILOFS_GBR_FS:
		gbrs_update_fs_gbr(gbrs);
		break;
	case SILOFS_GBR_AR:
		gbrs_update_ar_gbr(gbrs);
		break;
	case SILOFS_GBR_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}
