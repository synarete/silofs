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
#include "obs.h"
#include "bootrec.h"
#include "fs.h"
#include "env.h"

static uint64_t bootrec1k_magic(const struct silofs_bootrec1k *bootrec1k)
{
	return silofs_le64_to_cpu(bootrec1k->br_magic);
}

static void
bootrec1k_set_magic(struct silofs_bootrec1k *bootrec1k, uint64_t magic)
{
	bootrec1k->br_magic = silofs_cpu_to_le64(magic);
}

static uint64_t bootrec1k_version(const struct silofs_bootrec1k *bootrec1k)
{
	return silofs_le64_to_cpu(bootrec1k->br_version);
}

static void
bootrec1k_set_version(struct silofs_bootrec1k *bootrec1k, uint64_t version)
{
	bootrec1k->br_version = silofs_cpu_to_le64(version);
}

static enum silofs_bootrecf
bootrec1k_flags(const struct silofs_bootrec1k *bootrec1k)
{
	const uint64_t f = silofs_le64_to_cpu(bootrec1k->br_flags);

	return (enum silofs_bootrecf)f;
}

static void
bootrec1k_set_flags(struct silofs_bootrec1k *bootrec1k, enum silofs_bootrecf f)
{
	bootrec1k->br_flags = silofs_cpu_to_le64((uint64_t)f);
}

static int32_t bootrec1k_chiper_algo(const struct silofs_bootrec1k *bootrec1k)
{
	return (int32_t)silofs_le32_to_cpu(bootrec1k->br_chiper_algo);
}

static int32_t bootrec1k_chiper_mode(const struct silofs_bootrec1k *bootrec1k)
{
	return (int32_t)silofs_le32_to_cpu(bootrec1k->br_chiper_mode);
}

static void bootrec1k_set_cipher(struct silofs_bootrec1k *bootrec1k,
                                 int32_t cipher_algo, int32_t cipher_mode)
{
	bootrec1k->br_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	bootrec1k->br_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

void silofs_bootrec1k_init(struct silofs_bootrec1k *bootrec1k)
{
	silofs_memzero(bootrec1k, sizeof(*bootrec1k));
	bootrec1k_set_magic(bootrec1k, SILOFS_BOOTREC_MAGIC);
	bootrec1k_set_version(bootrec1k, SILOFS_FMT_VERSION);
	bootrec1k_set_flags(bootrec1k, SILOFS_BOOTRECF_NONE);
	bootrec1k_set_cipher(bootrec1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                     SILOFS_CIPHER_MODE_DEFAULT);
}

void silofs_bootrec1k_fini(struct silofs_bootrec1k *bootrec1k)
{
	silofs_memffff(bootrec1k, sizeof(*bootrec1k));
}

static void bootrec1k_sb_uaddr(const struct silofs_bootrec1k *bootrec1k,
                               struct silofs_uaddr *out_sb_uaddr)
{
	silofs_uaddr96b_xtoh(&bootrec1k->br_sb_uaddr, out_sb_uaddr);
}

static void bootrec1k_set_sb_uaddr(struct silofs_bootrec1k *bootrec1k,
                                   const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr96b_htox(&bootrec1k->br_sb_uaddr, sb_uaddr);
}

static void bootrec1k_main_ivkey(const struct silofs_bootrec1k *bootrec1k,
                                 struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &bootrec1k->br_main_key,
	                   &bootrec1k->br_main_iv);
}

static void bootrec1k_set_main_ivkey(struct silofs_bootrec1k *bootrec1k,
                                     const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&bootrec1k->br_main_key, &ivkey->key);
	silofs_iv_assign(&bootrec1k->br_main_iv, &ivkey->iv);
}

static int bootrec1k_check_base(const struct silofs_bootrec1k *bootrec1k)
{
	const uint64_t magic = bootrec1k_magic(bootrec1k);
	const uint64_t version = bootrec1k_version(bootrec1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_BOOTREC_MAGIC) &&
	    (version != SILOFS_FMT_VERSION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_BOOTREC_MAGIC) {
		log_dbg("bad bootrec magic: 0x%lx", magic);
		return -SILOFS_EBADBOOTREC;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad bootrec version: %lu", version);
		return -SILOFS_EBADBOOTREC;
	}
	return 0;
}

static int bootrec1k_check_uaddr_sb(const struct silofs_bootrec1k *bootrec1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_ltype ltype;

	bootrec1k_sb_uaddr(bootrec1k, &uaddr);
	height = silofs_uaddr_height(&uaddr);
	ltype = silofs_uaddr_ltype(&uaddr);
	if ((ltype != SILOFS_LTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad bootrec uaddr-sb: voff=%ld ltype=%d height=%d",
		        uaddr.voff, (int)ltype, (int)height);
		return -SILOFS_EBADBOOTREC;
	}
	return 0;
}

static void bootrec1k_uuid(const struct silofs_bootrec1k *bootrec1k,
                           struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &bootrec1k->br_uuid);
}

static void bootrec1k_set_uuid(struct silofs_bootrec1k *bootrec1k,
                               const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&bootrec1k->br_uuid, uuid);
}

static int bootrec1k_check(const struct silofs_bootrec1k *bootrec1k)
{
	int algo;
	int mode;
	int err;

	err = bootrec1k_check_base(bootrec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_check_uaddr_sb(bootrec1k);
	if (err) {
		return err;
	}
	algo = bootrec1k_chiper_algo(bootrec1k);
	mode = bootrec1k_chiper_mode(bootrec1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static void bootrec1k_hash(const struct silofs_bootrec1k *bootrec1k,
                           struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &bootrec1k->br_hash);
}

static void bootrec1k_set_hash(struct silofs_bootrec1k *bootrec1k,
                               const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&bootrec1k->br_hash, hash);
}

static void bootrec1k_calc_hash(const struct silofs_bootrec1k *bootrec1k,
                                const struct silofs_mdigest *md,
                                struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_bootrec1k, br_hash);

	silofs_sha3_256_of(md, bootrec1k, len, out_hash);
}

void silofs_bootrec1k_stamp(struct silofs_bootrec1k *bootrec1k,
                            const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	bootrec1k_calc_hash(bootrec1k, md, &hash);
	bootrec1k_set_hash(bootrec1k, &hash);
}

static int bootrec1k_check_hash(const struct silofs_bootrec1k *bootrec1k,
                                const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	bootrec1k_hash(bootrec1k, &hash[0]);
	bootrec1k_calc_hash(bootrec1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int bootrec1k_verify(const struct silofs_bootrec1k *bootrec1k,
                            const struct silofs_mdigest *md)
{
	int err;

	err = bootrec1k_check(bootrec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_check_hash(bootrec1k, md);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *bootrec1k,
                            const struct silofs_mdigest *md)
{
	return bootrec1k_verify(bootrec1k, md);
}

void silofs_bootrec1k_xtoh(const struct silofs_bootrec1k *bootrec1k,
                           struct silofs_bootrec *bootrec)
{
	bootrec1k_uuid(bootrec1k, &bootrec->uuid);
	bootrec1k_main_ivkey(bootrec1k, &bootrec->main_ivkey);
	bootrec1k_sb_uaddr(bootrec1k, &bootrec->sb_uaddr);
	bootrec->flags = bootrec1k_flags(bootrec1k);
	bootrec->cipher_algo = (int32_t)bootrec1k_chiper_algo(bootrec1k);
	bootrec->cipher_mode = (int32_t)bootrec1k_chiper_mode(bootrec1k);
}

void silofs_bootrec1k_htox(struct silofs_bootrec1k *bootrec1k,
                           const struct silofs_bootrec *bootrec)
{
	silofs_bootrec1k_init(bootrec1k);
	bootrec1k_set_sb_uaddr(bootrec1k, &bootrec->sb_uaddr);
	bootrec1k_set_flags(bootrec1k, bootrec->flags);
	bootrec1k_set_uuid(bootrec1k, &bootrec->uuid);
	bootrec1k_set_main_ivkey(bootrec1k, &bootrec->main_ivkey);
	bootrec1k_set_cipher(bootrec1k, bootrec->cipher_algo,
	                     bootrec->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *bootrec)
{
	silofs_memzero(bootrec, sizeof(*bootrec));
	silofs_uaddr_reset(&bootrec->sb_uaddr);
	bootrec->flags = SILOFS_BOOTRECF_NONE;
	bootrec->cipher_algo = SILOFS_CIPHER_AES256;
	bootrec->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_bootrec_fini(struct silofs_bootrec *bootrec)
{
	silofs_memffff(bootrec, sizeof(*bootrec));
}

void silofs_bootrec_assign(struct silofs_bootrec *bootrec,
                           const struct silofs_bootrec *other)
{
	silofs_uuid_assign(&bootrec->uuid, &other->uuid);
	silofs_ivkey_assign(&bootrec->main_ivkey, &other->main_ivkey);
	silofs_uaddr_assign(&bootrec->sb_uaddr, &other->sb_uaddr);
	bootrec->flags = other->flags;
	bootrec->cipher_algo = other->cipher_algo;
	bootrec->cipher_mode = other->cipher_mode;
}

void silofs_bootrec_gen_uuid(struct silofs_bootrec *bootrec)
{
	silofs_uuid_generate(&bootrec->uuid);
}

void silofs_bootrec_set_ivkey(struct silofs_bootrec *bootrec,
                              const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&bootrec->main_ivkey, ivkey);
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

int silofs_bootrec_gen_ivkey(struct silofs_bootrec *bootrec,
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
	silofs_bootrec_set_ivkey(bootrec, &ivkey[0]);
	return 0;
}

void silofs_bootrec_sb_uaddr(const struct silofs_bootrec *bootrec,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_assign(out_uaddr, &bootrec->sb_uaddr);
}

void silofs_bootrec_set_sb_uaddr(struct silofs_bootrec *bootrec,
                                 const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&bootrec->sb_uaddr, uaddr);
}

void silofs_bootrec_blobid(const struct silofs_bootrec *bootrec,
                           struct silofs_blobid *out_vid)
{
	const struct silofs_uaddr *sb_uaddr = &bootrec->sb_uaddr;

	silofs_blobid_assign(out_vid, &sb_uaddr->laddr.lsid.blobid);
}

static void bootrec_uaddr_by_blobid(const struct silofs_blobid *blobid,
                                    struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const enum silofs_ltype ltype = SILOFS_LTYPE_BOOTREC;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsid_setup(&lsid, blobid, 0, ltype, height, ltype);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

void silofs_make_bootrec_uaddr(const struct silofs_blobid *blobid,
                               struct silofs_uaddr *out_uaddr)
{
	bootrec_uaddr_by_blobid(blobid, out_uaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int encrypt_bootrec1k(const struct silofs_cipher *ci,
                             const struct silofs_ivkey *ivkey,
                             const struct silofs_bootrec1k *bootrec1k_in,
                             struct silofs_bootrec1k *bootrec1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, bootrec1k_in, bootrec1k_out,
	                          sizeof(*bootrec1k_out));
}

static int decrypt_bootrec1k(const struct silofs_cipher *ci,
                             const struct silofs_ivkey *ivkey,
                             const struct silofs_bootrec1k *bootrec1k_in,
                             struct silofs_bootrec1k *bootrec1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, bootrec1k_in, bootrec1k_out,
	                          sizeof(*bootrec1k_out));
}

static int bootrec_encode(const struct silofs_bootrec *bootrec,
                          const struct silofs_mdigest *mdigest,
                          const struct silofs_cipher *cipher,
                          const struct silofs_ivkey *ivkey,
                          struct silofs_bootrec1k *out_bootrec1k)
{
	struct silofs_bootrec1k bootrec1k;

	silofs_bootrec1k_htox(&bootrec1k, bootrec);
	silofs_bootrec1k_stamp(&bootrec1k, mdigest);
	return encrypt_bootrec1k(cipher, ivkey, &bootrec1k, out_bootrec1k);
}

static int bootrec_decode(struct silofs_bootrec *bootrec,
                          const struct silofs_mdigest *mdigest,
                          const struct silofs_cipher *cipher,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_bootrec1k *bootrec1k_enc)
{
	struct silofs_bootrec1k bootrec1k = { .br_magic = 1 };
	int err;

	err = decrypt_bootrec1k(cipher, ivkey, bootrec1k_enc, &bootrec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_verify(&bootrec1k, mdigest);
	if (err) {
		return err;
	}
	silofs_bootrec1k_xtoh(&bootrec1k, bootrec);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_encode_bootrec(const struct silofs_env *env,
                          const struct silofs_bootrec *bootrec,
                          struct silofs_bootrec1k *out_bootrec1k)
{
	return bootrec_encode(bootrec, &env->mdigest, &env->bootrec_cipher,
	                      &env->bootrec_ivkey, out_bootrec1k);
}

int silofs_decode_bootrec(const struct silofs_env *env,
                          const struct silofs_bootrec1k *bootrec1k_enc,
                          struct silofs_bootrec *out_bootrec)
{
	return bootrec_decode(out_bootrec, &env->mdigest, &env->bootrec_cipher,
	                      &env->bootrec_ivkey, bootrec1k_enc);
}

static void calc_bootrec1k_caddr(const struct silofs_env *env,
                                 const struct silofs_bootrec1k *bootrec1k,
                                 struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = unconst(bootrec1k),
		.iov_len = sizeof(*bootrec1k),
	};
	const enum silofs_ctype ctype = SILOFS_CTYPE_BOOTREC;

	silofs_calc_caddr_of(&env->mdigest, &iov, 1, ctype, out_caddr);
}

static int verify_bootrec1k_caddr(const struct silofs_env *env,
                                  const struct silofs_bootrec1k *bootrec1k,
                                  const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_bootrec1k_caddr(env, bootrec1k, &caddr2);
	return silofs_caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADBOOTREC;
}

int silofs_calc_bootrec_caddr(const struct silofs_env *env,
                              const struct silofs_bootrec *bootrec,
                              struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec1k bootrec1k_enc = {
		.br_magic = 1,
	};
	int err;

	err = silofs_encode_bootrec(env, bootrec, &bootrec1k_enc);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	calc_bootrec1k_caddr(env, &bootrec1k_enc, out_caddr);
	return 0;
}

int silofs_save_bootrec(const struct silofs_env *env,
                        const struct silofs_bootrec *bootrec,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec1k bootrec1k_enc = {
		.br_magic = 1,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &bootrec1k_enc,
		.rov_len = sizeof(bootrec1k_enc),
	};
	struct silofs_caddr caddr;
	int err;

	err = silofs_encode_bootrec(env, bootrec, &bootrec1k_enc);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	calc_bootrec1k_caddr(env, &bootrec1k_enc, &caddr);
	err = silofs_repo_save_cobj(env->base.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save bootrec: err=%d", err);
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

int silofs_load_bootrec(const struct silofs_env *env,
                        const struct silofs_caddr *caddr,
                        struct silofs_bootrec *out_bootrec)
{
	struct silofs_bootrec1k bootrec1k_enc = { .br_magic = 0 };
	struct silofs_rwvec rwvec = {
		.rwv_base = &bootrec1k_enc,
		.rwv_len = sizeof(bootrec1k_enc),
	};
	int err;

	err = silofs_repo_lookup_ref(env->base.repo, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
	err = silofs_repo_load_cobj(env->base.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load bootrec: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOBOOTREC : err;
	}
	err = verify_bootrec1k_caddr(env, &bootrec1k_enc, caddr);
	if (err) {
		log_dbg("failed to verify bootrec: err=%d", err);
		return err;
	}
	err = silofs_decode_bootrec(env, &bootrec1k_enc, out_bootrec);
	if (err) {
		log_dbg("failed to decode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_stat_bootrec(const struct silofs_env *env,
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
		log_err("failed to stat bootrec: err=%d", err);
		return err;
	}
	if (sz != SILOFS_BOOTREC_SIZE) {
		log_warn("bad bootrec: size=%zu", sz);
		return -SILOFS_EBADBOOTREC;
	}
	return 0;
}

int silofs_reload_bootrec(struct silofs_env *env,
                          const struct silofs_caddr *caddr,
                          struct silofs_bootrec *out_bootrec)
{
	int err;

	err = silofs_stat_bootrec(env, caddr);
	if (err) {
		return err;
	}
	err = silofs_load_bootrec(env, caddr, out_bootrec);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, out_bootrec);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_unlink_bootrec(const struct silofs_env *env,
                          const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink bootrec: err=%d", err);
		return err;
	}
	err = silofs_repo_remove_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}
