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
#include "mrec.h"
#include "fs.h"
#include "env.h"

static uint64_t mrec1k_magic(const struct silofs_mrec1k *mrec1k)
{
	return silofs_le64_to_cpu(mrec1k->mrec_magic);
}

static void mrec1k_set_magic(struct silofs_mrec1k *mrec1k, uint64_t magic)
{
	mrec1k->mrec_magic = silofs_cpu_to_le64(magic);
}

static uint64_t mrec1k_version(const struct silofs_mrec1k *mrec1k)
{
	return silofs_le64_to_cpu(mrec1k->mrec_version);
}

static void mrec1k_set_version(struct silofs_mrec1k *mrec1k, uint64_t version)
{
	mrec1k->mrec_version = silofs_cpu_to_le64(version);
}

static enum silofs_mrecf mrec1k_flags(const struct silofs_mrec1k *mrec1k)
{
	const uint64_t f = silofs_le64_to_cpu(mrec1k->mrec_flags);

	return (enum silofs_mrecf)f;
}

static void mrec1k_set_flags(struct silofs_mrec1k *mrec1k, enum silofs_mrecf f)
{
	mrec1k->mrec_flags = silofs_cpu_to_le64((uint64_t)f);
}

static int32_t mrec1k_chiper_algo(const struct silofs_mrec1k *mrec1k)
{
	return (int32_t)silofs_le32_to_cpu(mrec1k->mrec_chiper_algo);
}

static int32_t mrec1k_chiper_mode(const struct silofs_mrec1k *mrec1k)
{
	return (int32_t)silofs_le32_to_cpu(mrec1k->mrec_chiper_mode);
}

static void mrec1k_set_cipher(struct silofs_mrec1k *mrec1k,
                              int32_t cipher_algo, int32_t cipher_mode)
{
	mrec1k->mrec_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	mrec1k->mrec_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

static void mrec1k_setup(struct silofs_mrec1k *mrec1k)
{
	silofs_memzero(mrec1k, sizeof(*mrec1k));
	mrec1k_set_magic(mrec1k, SILOFS_MBR_MAGIC);
	mrec1k_set_version(mrec1k, SILOFS_FMT_VERSION);
	mrec1k_set_flags(mrec1k, SILOFS_MRECF_NONE);
	mrec1k_set_cipher(mrec1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                  SILOFS_CIPHER_MODE_DEFAULT);
}

static void mrec1k_sb_addr(const struct silofs_mrec1k *mrec1k,
                           struct silofs_uaddr *out_sb_addr)
{
	silofs_uaddr96b_xtoh(&mrec1k->mrec_sb_addr, out_sb_addr);
}

static void mrec1k_set_sb_addr(struct silofs_mrec1k *mrec1k,
                               const struct silofs_uaddr *sb_addr)
{
	silofs_uaddr96b_htox(&mrec1k->mrec_sb_addr, sb_addr);
}

static void mrec1k_arix_addr(const struct silofs_mrec1k *mrec1k,
                             struct silofs_caddr *out_arix_addr)
{
	silofs_caddr64b_xtoh(&mrec1k->mrec_arix_addr, out_arix_addr);
}

static void mrec1k_set_arix_addr(struct silofs_mrec1k *mrec1k,
                                 const struct silofs_caddr *arix_addr)
{
	silofs_caddr64b_htox(&mrec1k->mrec_arix_addr, arix_addr);
}

static void mrec1k_main_ivkey(const struct silofs_mrec1k *mrec1k,
                              struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &mrec1k->mrec_main_key,
	                   &mrec1k->mrec_main_iv);
}

static void mrec1k_set_main_ivkey(struct silofs_mrec1k *mrec1k,
                                  const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&mrec1k->mrec_main_key, &ivkey->key);
	silofs_iv_assign(&mrec1k->mrec_main_iv, &ivkey->iv);
}

static int mrec1k_check_base(const struct silofs_mrec1k *mrec1k)
{
	const uint64_t magic = mrec1k_magic(mrec1k);
	const uint64_t version = mrec1k_version(mrec1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_MBR_MAGIC) && (version != SILOFS_FMT_VERSION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad mrec magic: 0x%lx", magic);
		return -SILOFS_EBADMBR;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad mrec version: %lu", version);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int mrec1k_check_uaddr_sb(const struct silofs_mrec1k *mrec1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_mtype mtype;

	mrec1k_sb_addr(mrec1k, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	height = silofs_uaddr_height(&uaddr);
	mtype = silofs_uaddr_mtype(&uaddr);
	if ((mtype != SILOFS_MTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad mrec uaddr-sb: voff=%ld mtype=%d height=%d",
		        uaddr.voff, (int)mtype, (int)height);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static void
mrec1k_uuid(const struct silofs_mrec1k *mrec1k, struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &mrec1k->mrec_uuid);
}

static void
mrec1k_set_uuid(struct silofs_mrec1k *mrec1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&mrec1k->mrec_uuid, uuid);
}

static int mrec1k_check(const struct silofs_mrec1k *mrec1k)
{
	int algo;
	int mode;
	int err;

	err = mrec1k_check_base(mrec1k);
	if (err) {
		return err;
	}
	err = mrec1k_check_uaddr_sb(mrec1k);
	if (err) {
		return err;
	}
	algo = mrec1k_chiper_algo(mrec1k);
	mode = mrec1k_chiper_mode(mrec1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static void
mrec1k_hash(const struct silofs_mrec1k *mrec1k, struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &mrec1k->mrec_hash);
}

static void mrec1k_set_hash(struct silofs_mrec1k *mrec1k,
                            const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&mrec1k->mrec_hash, hash);
}

static void mrec1k_calc_hash(const struct silofs_mrec1k *mrec1k,
                             const struct silofs_mdigest *md,
                             struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_mrec1k, mrec_hash);

	silofs_sha3_256_of(md, mrec1k, len, out_hash);
}

static void
mrec1k_stamp(struct silofs_mrec1k *mrec1k, const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	mrec1k_calc_hash(mrec1k, md, &hash);
	mrec1k_set_hash(mrec1k, &hash);
}

static int mrec1k_check_hash(const struct silofs_mrec1k *mrec1k,
                             const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	mrec1k_hash(mrec1k, &hash[0]);
	mrec1k_calc_hash(mrec1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int mrec1k_verify(const struct silofs_mrec1k *mrec1k,
                         const struct silofs_mdigest *md)
{
	int err;

	err = mrec1k_check(mrec1k);
	if (err) {
		return err;
	}
	err = mrec1k_check_hash(mrec1k, md);
	if (err) {
		return err;
	}
	return 0;
}

static void
mrec1k_xtoh(const struct silofs_mrec1k *mrec1k, struct silofs_mrec *mrec)
{
	mrec1k_uuid(mrec1k, &mrec->uuid);
	mrec1k_main_ivkey(mrec1k, &mrec->main_ivkey);
	mrec1k_sb_addr(mrec1k, &mrec->sb_addr);
	mrec1k_arix_addr(mrec1k, &mrec->ar_addr);
	mrec->flags = mrec1k_flags(mrec1k);
	mrec->cipher_algo = (int32_t)mrec1k_chiper_algo(mrec1k);
	mrec->cipher_mode = (int32_t)mrec1k_chiper_mode(mrec1k);
}

static void
mrec1k_htox(struct silofs_mrec1k *mrec1k, const struct silofs_mrec *mrec)
{
	mrec1k_setup(mrec1k);
	mrec1k_set_sb_addr(mrec1k, &mrec->sb_addr);
	mrec1k_set_arix_addr(mrec1k, &mrec->ar_addr);
	mrec1k_set_flags(mrec1k, mrec->flags);
	mrec1k_set_uuid(mrec1k, &mrec->uuid);
	mrec1k_set_main_ivkey(mrec1k, &mrec->main_ivkey);
	mrec1k_set_cipher(mrec1k, mrec->cipher_algo, mrec->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mrec_init(struct silofs_mrec *mrec)
{
	silofs_memzero(mrec, sizeof(*mrec));
	silofs_uaddr_reset(&mrec->sb_addr);
	silofs_caddr_reset(&mrec->ar_addr);
	mrec->flags = SILOFS_MRECF_NONE;
	mrec->cipher_algo = SILOFS_CIPHER_AES256;
	mrec->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_mrec_fini(struct silofs_mrec *mrec)
{
	silofs_ivkey_reset(&mrec->main_ivkey);
	silofs_uaddr_reset(&mrec->sb_addr);
	silofs_caddr_reset(&mrec->ar_addr);
	mrec->flags = SILOFS_MRECF_NONE;
}

void silofs_mrec_assign(struct silofs_mrec *mrec,
                        const struct silofs_mrec *other)
{
	silofs_uuid_assign(&mrec->uuid, &other->uuid);
	silofs_ivkey_assign(&mrec->main_ivkey, &other->main_ivkey);
	silofs_uaddr_assign(&mrec->sb_addr, &other->sb_addr);
	silofs_caddr_assign(&mrec->ar_addr, &other->ar_addr);
	mrec->cipher_algo = other->cipher_algo;
	mrec->cipher_mode = other->cipher_mode;
	mrec->flags = other->flags;
}

void silofs_mrec_gen_uuid(struct silofs_mrec *mrec)
{
	silofs_uuid_generate(&mrec->uuid);
}

void silofs_mrec_set_ivkey(struct silofs_mrec *mrec,
                           const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&mrec->main_ivkey, ivkey);
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

int silofs_mrec_gen_ivkey(struct silofs_mrec *mrec,
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
	silofs_mrec_set_ivkey(mrec, &ivkey[0]);
	return 0;
}

void silofs_mrec_set_sb_addr(struct silofs_mrec *mrec,
                             const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&mrec->sb_addr, uaddr);
}

static void
mrec_update_flags(struct silofs_mrec *mrec, enum silofs_mrecf mask, bool set)
{
	if (set) {
		mrec->flags |= mask;
	} else {
		mrec->flags &= ~mask;
	}
}

void silofs_mrec_set_ar_addr(struct silofs_mrec *mrec,
                             const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&mrec->ar_addr, caddr);
	mrec_update_flags(mrec, SILOFS_MRECF_ARCH,
	                  !silofs_caddr_isnone(caddr));
}

void silofs_make_mrec_uaddr(const struct silofs_blobid *blobid,
                            struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const enum silofs_mtype mtype = SILOFS_MTYPE_MBR;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsid_setup(&lsid, blobid, 0, mtype, height, mtype);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int encrypt_mrec1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_mrec1k *mrec1k_in,
                          struct silofs_mrec1k *mrec1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, mrec1k_in, mrec1k_out,
	                          sizeof(*mrec1k_out));
}

static int decrypt_mrec1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_mrec1k *mrec1k_in,
                          struct silofs_mrec1k *mrec1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, mrec1k_in, mrec1k_out,
	                          sizeof(*mrec1k_out));
}

static int
mrec_encode(const struct silofs_mrec *mrec,
            const struct silofs_mdigest *mdigest,
            const struct silofs_cipher *cipher,
            const struct silofs_ivkey *ivkey, struct silofs_mrec1k *out_mrec1k)
{
	struct silofs_mrec1k mrec1k;

	mrec1k_htox(&mrec1k, mrec);
	mrec1k_stamp(&mrec1k, mdigest);
	return encrypt_mrec1k(cipher, ivkey, &mrec1k, out_mrec1k);
}

static int
mrec_decode(struct silofs_mrec *mrec, const struct silofs_mdigest *mdigest,
            const struct silofs_cipher *cipher,
            const struct silofs_ivkey *ivkey,
            const struct silofs_mrec1k *mrec1k_enc)
{
	struct silofs_mrec1k mrec1k = { .mrec_magic = 1 };
	int err;

	err = decrypt_mrec1k(cipher, ivkey, mrec1k_enc, &mrec1k);
	if (err) {
		return err;
	}
	err = mrec1k_verify(&mrec1k, mdigest);
	if (err) {
		return err;
	}
	mrec1k_xtoh(&mrec1k, mrec);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mrecinfo_init(struct silofs_mrecinfo *mreci)
{
	int err;

	silofs_caddr_reset(&mreci->mref);
	silofs_mrec_init(&mreci->mrec);
	silofs_ivkey_init(&mreci->ivkey);

	err = silofs_cipher_init(&mreci->cipher);
	if (err) {
		return err;
	}
	err = silofs_mdigest_init(&mreci->mdigest);
	if (err) {
		silofs_cipher_fini(&mreci->cipher);
		return err;
	}
	return 0;
}

void silofs_mrecinfo_fini(struct silofs_mrecinfo *mreci)
{
	silofs_caddr_reset(&mreci->mref);
	silofs_mdigest_fini(&mreci->mdigest);
	silofs_cipher_fini(&mreci->cipher);
	silofs_ivkey_reset(&mreci->ivkey);
	silofs_mrec_fini(&mreci->mrec);
}

static int mreci_encode(const struct silofs_mrecinfo *mreci,
                        struct silofs_mrec1k *out_mrec1k)
{
	return mrec_encode(&mreci->mrec, &mreci->mdigest, &mreci->cipher,
	                   &mreci->ivkey, out_mrec1k);
}

static int
mreci_decode(struct silofs_mrecinfo *mreci, const struct silofs_mrec1k *mrec1k)
{
	return mrec_decode(&mreci->mrec, &mreci->mdigest, &mreci->cipher,
	                   &mreci->ivkey, mrec1k);
}

static void
mreci_set_ref(struct silofs_mrecinfo *mreci, const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&mreci->mref, caddr);
}

bool silofs_mrecinfo_has_ref(const struct silofs_mrecinfo *mreci,
                             const struct silofs_caddr *caddr)
{
	return silofs_caddr_isequal(&mreci->mref, caddr);
}

int silofs_mrecinfo_regen(struct silofs_mrecinfo *mreci)
{
	struct silofs_mrec1k mrec1k = {
		.mrec_magic = UINT64_MAX,
	};
	struct silofs_mrec *mrec = &mreci->mrec;
	int err;

	silofs_mrec_gen_uuid(mrec);
	err = silofs_mrec_gen_ivkey(mrec, &mreci->mdigest);
	if (err) {
		return err;
	}
	err = silofs_mrecinfo_encode(mreci, &mrec1k);
	if (err) {
		return err;
	}
	err = silofs_mrecinfo_decode(mreci, &mrec1k);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_mrecinfo_update_sb(struct silofs_mrecinfo *mreci,
                              const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_mrec1k mrec1k = {
		.mrec_magic = UINT64_MAX,
	};

	silofs_mrec_set_sb_addr(&mreci->mrec, sb_uaddr);
	return silofs_mrecinfo_encode(mreci, &mrec1k);
}

static void mreci_calc_addr_of(const struct silofs_mrecinfo *mreci,
                               const struct silofs_mrec1k *mrec1k_enc,
                               struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(mrec1k_enc),
		.iov_len = sizeof(*mrec1k_enc),
	};
	const enum silofs_ctype ctype = SILOFS_CTYPE_MBR;

	silofs_calc_caddr_of(&mreci->mdigest, &iov, 1, ctype, out_caddr);
}

int silofs_mrecinfo_encode(struct silofs_mrecinfo *mreci,
                           struct silofs_mrec1k *out_mrec1k_enc)
{
	struct silofs_caddr caddr;
	int err;

	err = mreci_encode(mreci, out_mrec1k_enc);
	if (err) {
		log_err("failed to encode mrec: err=%d", err);
		return err;
	}
	mreci_calc_addr_of(mreci, out_mrec1k_enc, &caddr);
	mreci_set_ref(mreci, &caddr);
	return 0;
}

int silofs_mrecinfo_decode(struct silofs_mrecinfo *mreci,
                           const struct silofs_mrec1k *mrec1k_enc)
{
	struct silofs_caddr caddr = {
		.ctype = SILOFS_CTYPE_NONE,
	};
	int err;

	mreci_calc_addr_of(mreci, mrec1k_enc, &caddr);
	err = mreci_decode(mreci, mrec1k_enc);
	if (err) {
		log_dbg("failed to encode mrec: err=%d", err);
		return err;
	}
	mreci_set_ref(mreci, &caddr);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_encode_mrec(const struct silofs_env *env,
                       const struct silofs_mrec *mrec,
                       struct silofs_mrec1k *out_mrec1k)
{
	return mrec_encode(mrec, &env->mreci.mdigest, &env->mreci.cipher,
	                   &env->mreci.ivkey, out_mrec1k);
}

int silofs_decode_mrec(const struct silofs_env *env,
                       const struct silofs_mrec1k *mrec1k_enc,
                       struct silofs_mrec *out_mrec)
{
	return mrec_decode(out_mrec, &env->mreci.mdigest, &env->mreci.cipher,
	                   &env->mreci.ivkey, mrec1k_enc);
}

static void calc_mrec1k_caddr(const struct silofs_env *env,
                              const struct silofs_mrec1k *mrec1k,
                              struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = unconst(mrec1k),
		.iov_len = sizeof(*mrec1k),
	};
	const enum silofs_ctype ctype = SILOFS_CTYPE_MBR;

	silofs_calc_caddr_of(&env->mdigest, &iov, 1, ctype, out_caddr);
}

static int verify_mrec1k_caddr(const struct silofs_env *env,
                               const struct silofs_mrec1k *mrec1k,
                               const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_mrec1k_caddr(env, mrec1k, &caddr2);
	return silofs_caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADMBR;
}

int silofs_calc_mrec_caddr(const struct silofs_env *env,
                           const struct silofs_mrec *mrec,
                           struct silofs_caddr *out_caddr)
{
	struct silofs_mrec1k mrec1k_enc = {
		.mrec_magic = 1,
	};
	int err;

	err = silofs_encode_mrec(env, mrec, &mrec1k_enc);
	if (err) {
		log_err("failed to encode mrec: err=%d", err);
		return err;
	}
	calc_mrec1k_caddr(env, &mrec1k_enc, out_caddr);
	return 0;
}

int silofs_save_mrec(const struct silofs_env *env,
                     const struct silofs_mrec *mrec,
                     struct silofs_caddr *out_caddr)
{
	struct silofs_mrec1k mrec1k_enc = {
		.mrec_magic = 1,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &mrec1k_enc,
		.rov_len = sizeof(mrec1k_enc),
	};
	struct silofs_caddr caddr;
	int err;

	err = silofs_encode_mrec(env, mrec, &mrec1k_enc);
	if (err) {
		log_err("failed to encode mrec: err=%d", err);
		return err;
	}
	calc_mrec1k_caddr(env, &mrec1k_enc, &caddr);
	err = silofs_repo_save_cobj(env->base.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save mrec: err=%d", err);
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

int silofs_load_mrec(const struct silofs_env *env,
                     const struct silofs_caddr *caddr,
                     struct silofs_mrec *out_mrec)
{
	struct silofs_mrec1k mrec1k_enc = { .mrec_magic = 0 };
	struct silofs_rwvec rwvec = {
		.rwv_base = &mrec1k_enc,
		.rwv_len = sizeof(mrec1k_enc),
	};
	int err;

	err = silofs_repo_lookup_ref(env->base.repo, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
	err = silofs_repo_load_cobj(env->base.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load mrec: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	err = verify_mrec1k_caddr(env, &mrec1k_enc, caddr);
	if (err) {
		log_dbg("failed to verify mrec: err=%d", err);
		return err;
	}
	err = silofs_decode_mrec(env, &mrec1k_enc, out_mrec);
	if (err) {
		log_dbg("failed to decode mrec: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_unlink_mrec(const struct silofs_env *env,
                       const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink mrec: err=%d", err);
		return err;
	}
	err = silofs_repo_remove_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}
