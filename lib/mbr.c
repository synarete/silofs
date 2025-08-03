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

static enum silofs_mbrf mbr1k_flags(const struct silofs_mbr1k *mbr1k)
{
	const uint64_t f = silofs_le64_to_cpu(mbr1k->mbr_flags);

	return (enum silofs_mbrf)f;
}

static void mbr1k_set_flags(struct silofs_mbr1k *mbr1k, enum silofs_mbrf f)
{
	mbr1k->mbr_flags = silofs_cpu_to_le64((uint64_t)f);
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
	mbr1k_set_flags(mbr1k, SILOFS_MBRF_NONE);
	mbr1k_set_cipher(mbr1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                 SILOFS_CIPHER_MODE_DEFAULT);
}

static void mbr1k_sb_uaddr(const struct silofs_mbr1k *mbr1k,
                           struct silofs_uaddr *out_sb_uaddr)
{
	silofs_uaddr96b_xtoh(&mbr1k->mbr_sb_uaddr, out_sb_uaddr);
}

static void mbr1k_set_sb_uaddr(struct silofs_mbr1k *mbr1k,
                               const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr96b_htox(&mbr1k->mbr_sb_uaddr, sb_uaddr);
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

	mbr1k_sb_uaddr(mbr1k, &uaddr);
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
	mbr1k_sb_uaddr(mbr1k, &mbr->sb_uaddr);
	mbr->flags = mbr1k_flags(mbr1k);
	mbr->cipher_algo = (int32_t)mbr1k_chiper_algo(mbr1k);
	mbr->cipher_mode = (int32_t)mbr1k_chiper_mode(mbr1k);
}

static void
mbr1k_htox(struct silofs_mbr1k *mbr1k, const struct silofs_mbr *mbr)
{
	mbr1k_setup(mbr1k);
	mbr1k_set_sb_uaddr(mbr1k, &mbr->sb_uaddr);
	mbr1k_set_flags(mbr1k, mbr->flags);
	mbr1k_set_uuid(mbr1k, &mbr->uuid);
	mbr1k_set_main_ivkey(mbr1k, &mbr->main_ivkey);
	mbr1k_set_cipher(mbr1k, mbr->cipher_algo, mbr->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbr_init(struct silofs_mbr *mbr)
{
	silofs_memzero(mbr, sizeof(*mbr));
	silofs_uaddr_reset(&mbr->sb_uaddr);
	silofs_caddr_reset(&mbr->ar_index);
	mbr->flags = SILOFS_MBRF_NONE;
	mbr->cipher_algo = SILOFS_CIPHER_AES256;
	mbr->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_mbr_fini(struct silofs_mbr *mbr)
{
	silofs_ivkey_reset(&mbr->main_ivkey);
	silofs_uaddr_reset(&mbr->sb_uaddr);
	silofs_caddr_reset(&mbr->ar_index);
	mbr->flags = SILOFS_MBRF_NONE;
}

void silofs_mbr_assign(struct silofs_mbr *mbr, const struct silofs_mbr *other)
{
	silofs_uuid_assign(&mbr->uuid, &other->uuid);
	silofs_ivkey_assign(&mbr->main_ivkey, &other->main_ivkey);
	silofs_uaddr_assign(&mbr->sb_uaddr, &other->sb_uaddr);
	silofs_caddr_assign(&mbr->ar_index, &other->ar_index);
	mbr->cipher_algo = other->cipher_algo;
	mbr->cipher_mode = other->cipher_mode;
	mbr->flags = other->flags;
}

void silofs_mbr_gen_uuid(struct silofs_mbr *mbr)
{
	silofs_uuid_generate(&mbr->uuid);
}

void silofs_mbr_set_ivkey(struct silofs_mbr *mbr,
                          const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&mbr->main_ivkey, ivkey);
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

int silofs_mbr_gen_ivkey(struct silofs_mbr *mbr,
                         const struct silofs_mdigest *md)
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
	silofs_mbr_set_ivkey(mbr, &ivkey[0]);
	return 0;
}

void silofs_mbr_sb_uaddr(const struct silofs_mbr *mbr,
                         struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_assign(out_uaddr, &mbr->sb_uaddr);
}

void silofs_mbr_set_sb_uaddr(struct silofs_mbr *mbr,
                             const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&mbr->sb_uaddr, uaddr);
}

void silofs_mbr_ar_index(const struct silofs_mbr *mbr,
                         struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &mbr->ar_index);
}

void silofs_mbr_set_ar_index(struct silofs_mbr *mbr,
                             const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&mbr->ar_index, caddr);
	if (silofs_caddr_isnone(caddr)) {
		mbr->flags &= ~SILOFS_MBRF_ARCH;
	} else {
		mbr->flags |= SILOFS_MBRF_ARCH;
	}
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static int
mbr_encode(const struct silofs_mbr *mbr, const struct silofs_mdigest *mdigest,
           const struct silofs_cipher *cipher,
           const struct silofs_ivkey *ivkey, struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbr1k mbr1k;

	mbr1k_htox(&mbr1k, mbr);
	mbr1k_stamp(&mbr1k, mdigest);
	return encrypt_mbr1k(cipher, ivkey, &mbr1k, out_mbr1k);
}

static int
mbr_decode(struct silofs_mbr *mbr, const struct silofs_mdigest *mdigest,
           const struct silofs_cipher *cipher,
           const struct silofs_ivkey *ivkey,
           const struct silofs_mbr1k *mbr1k_enc)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 1 };
	int err;

	err = decrypt_mbr1k(cipher, ivkey, mbr1k_enc, &mbr1k);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_encode_mbr(const struct silofs_env *env,
                      const struct silofs_mbr *mbr,
                      struct silofs_mbr1k *out_mbr1k)
{
	return mbr_encode(mbr, &env->mdigest, &env->mbr_cipher,
	                  &env->mbr_ivkey, out_mbr1k);
}

int silofs_decode_mbr(const struct silofs_env *env,
                      const struct silofs_mbr1k *mbr1k_enc,
                      struct silofs_mbr *out_mbr)
{
	return mbr_decode(out_mbr, &env->mdigest, &env->mbr_cipher,
	                  &env->mbr_ivkey, mbr1k_enc);
}

static void calc_mbr1k_caddr(const struct silofs_env *env,
                             const struct silofs_mbr1k *mbr1k,
                             struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = unconst(mbr1k),
		.iov_len = sizeof(*mbr1k),
	};
	const enum silofs_ctype ctype = SILOFS_CTYPE_MBR;

	silofs_calc_caddr_of(&env->mdigest, &iov, 1, ctype, out_caddr);
}

static int verify_mbr1k_caddr(const struct silofs_env *env,
                              const struct silofs_mbr1k *mbr1k,
                              const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_mbr1k_caddr(env, mbr1k, &caddr2);
	return silofs_caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADMBR;
}

int silofs_calc_mbr_caddr(const struct silofs_env *env,
                          const struct silofs_mbr *mbr,
                          struct silofs_caddr *out_caddr)
{
	struct silofs_mbr1k mbr1k_enc = {
		.mbr_magic = 1,
	};
	int err;

	err = silofs_encode_mbr(env, mbr, &mbr1k_enc);
	if (err) {
		log_err("failed to encode mbr: err=%d", err);
		return err;
	}
	calc_mbr1k_caddr(env, &mbr1k_enc, out_caddr);
	return 0;
}

int silofs_save_mbr(const struct silofs_env *env, const struct silofs_mbr *mbr,
                    struct silofs_caddr *out_caddr)
{
	struct silofs_mbr1k mbr1k_enc = {
		.mbr_magic = 1,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &mbr1k_enc,
		.rov_len = sizeof(mbr1k_enc),
	};
	struct silofs_caddr caddr;
	int err;

	err = silofs_encode_mbr(env, mbr, &mbr1k_enc);
	if (err) {
		log_err("failed to encode mbr: err=%d", err);
		return err;
	}
	calc_mbr1k_caddr(env, &mbr1k_enc, &caddr);
	err = silofs_repo_save_cobj(env->base.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	err = silofs_repo_create_ref(env->base.repo, &caddr);
	if (err) {
		log_err("failed to create ref: err=%d", err);
		return err;
	}
	silofs_caddr_assign(out_caddr, &caddr);
	return 0;
}

int silofs_load_mbr(const struct silofs_env *env,
                    const struct silofs_caddr *caddr,
                    struct silofs_mbr *out_mbr)
{
	struct silofs_mbr1k mbr1k_enc = { .mbr_magic = 0 };
	struct silofs_rwvec rwvec = {
		.rwv_base = &mbr1k_enc,
		.rwv_len = sizeof(mbr1k_enc),
	};
	int err;

	err = silofs_repo_lookup_ref(env->base.repo, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
	err = silofs_repo_load_cobj(env->base.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load mbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	err = verify_mbr1k_caddr(env, &mbr1k_enc, caddr);
	if (err) {
		log_dbg("failed to verify mbr: err=%d", err);
		return err;
	}
	err = silofs_decode_mbr(env, &mbr1k_enc, out_mbr);
	if (err) {
		log_dbg("failed to decode mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_stat_mbr(const struct silofs_env *env,
                    const struct silofs_caddr *caddr)
{
	size_t sz = 0;
	int err;

	err = silofs_repo_lookup_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to lookup ref: err=%d", err);
		return err;
	}
	err = silofs_repo_stat_cobj(env->base.repo, caddr, &sz);
	if (err) {
		log_err("failed to stat mbr: err=%d", err);
		return err;
	}
	if (sz != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zu", sz);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_reload_mbr(struct silofs_env *env, const struct silofs_caddr *caddr,
                      struct silofs_mbr *out_mbr)
{
	int err;

	err = silofs_stat_mbr(env, caddr);
	if (err) {
		return err;
	}
	err = silofs_load_mbr(env, caddr, out_mbr);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, out_mbr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_unlink_mbr(const struct silofs_env *env,
                      const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink mbr: err=%d", err);
		return err;
	}
	err = silofs_repo_remove_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}
