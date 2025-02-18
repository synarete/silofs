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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>

static uint64_t uber1k_magic(const struct silofs_uber1k *uber1k)
{
	return silofs_le64_to_cpu(uber1k->ub_magic);
}

static void uber1k_set_magic(struct silofs_uber1k *uber1k, uint64_t magic)
{
	uber1k->ub_magic = silofs_cpu_to_le64(magic);
}

static uint64_t uber1k_version(const struct silofs_uber1k *uber1k)
{
	return silofs_le64_to_cpu(uber1k->ub_version);
}

static void uber1k_set_version(struct silofs_uber1k *uber1k, uint64_t version)
{
	uber1k->ub_version = silofs_cpu_to_le64(version);
}

static enum silofs_uberf uber1k_flags(const struct silofs_uber1k *uber1k)
{
	const uint64_t f = silofs_le64_to_cpu(uber1k->ub_flags);

	return (enum silofs_uberf)f;
}

static void uber1k_set_flags(struct silofs_uber1k *uber1k, enum silofs_uberf f)
{
	uber1k->ub_flags = silofs_cpu_to_le64((uint64_t)f);
}

static int32_t uber1k_chiper_algo(const struct silofs_uber1k *uber1k)
{
	return (int32_t)silofs_le32_to_cpu(uber1k->ub_chiper_algo);
}

static int32_t uber1k_chiper_mode(const struct silofs_uber1k *uber1k)
{
	return (int32_t)silofs_le32_to_cpu(uber1k->ub_chiper_mode);
}

static void uber1k_set_cipher(struct silofs_uber1k *uber1k,
                              int32_t cipher_algo, int32_t cipher_mode)
{
	uber1k->ub_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	uber1k->ub_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

void silofs_uber1k_init(struct silofs_uber1k *uber1k)
{
	silofs_memzero(uber1k, sizeof(*uber1k));
	uber1k_set_magic(uber1k, SILOFS_UBER_MAGIC);
	uber1k_set_version(uber1k, SILOFS_FMT_VERSION);
	uber1k_set_flags(uber1k, SILOFS_UBERF_NONE);
	uber1k_set_cipher(uber1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                  SILOFS_CIPHER_MODE_DEFAULT);
}

void silofs_uber1k_fini(struct silofs_uber1k *uber1k)
{
	silofs_memffff(uber1k, sizeof(*uber1k));
}

static void uber1k_sb_uaddr(const struct silofs_uber1k *uber1k,
                            struct silofs_uaddr *out_sb_uaddr)
{
	silofs_uaddr64b_xtoh(&uber1k->ub_sb_uaddr, out_sb_uaddr);
}

static void uber1k_set_sb_uaddr(struct silofs_uber1k *uber1k,
                                const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr64b_htox(&uber1k->ub_sb_uaddr, sb_uaddr);
}

static void
uber1k_sb_riv(const struct silofs_uber1k *uber1k, struct silofs_iv *out_sb_riv)
{
	silofs_iv_assign(out_sb_riv, &uber1k->ub_sb_riv);
}

static void
uber1k_set_sb_riv(struct silofs_uber1k *uber1k, const struct silofs_iv *sb_riv)
{
	silofs_iv_assign(&uber1k->ub_sb_riv, sb_riv);
}

static void uber1k_main_ivkey(const struct silofs_uber1k *uber1k,
                              struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &uber1k->ub_main_key,
	                   &uber1k->ub_main_iv);
}

static void uber1k_set_main_ivkey(struct silofs_uber1k *uber1k,
                                  const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&uber1k->ub_main_key, &ivkey->key);
	silofs_iv_assign(&uber1k->ub_main_iv, &ivkey->iv);
}

static void uber1k_pvsegr(const struct silofs_uber1k *uber1k,
                          struct silofs_pvsegr *out_pvsegr)
{
	silofs_pvsegr64b_xtoh(&uber1k->ub_pvsegr, out_pvsegr);
}

static void uber1k_set_pvsegr(struct silofs_uber1k *uber1k,
                              const struct silofs_pvsegr *pvsegr)
{
	silofs_pvsegr64b_htox(&uber1k->ub_pvsegr, pvsegr);
}

static int uber1k_check_base(const struct silofs_uber1k *uber1k)
{
	const uint64_t magic = uber1k_magic(uber1k);
	const uint64_t version = uber1k_version(uber1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_UBER_MAGIC) && (version != SILOFS_FMT_VERSION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_UBER_MAGIC) {
		log_dbg("bad uber magic: 0x%lx", magic);
		return -SILOFS_EBADUBER;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad uber version: %lu", version);
		return -SILOFS_EBADUBER;
	}
	return 0;
}

static int uber1k_check_uaddr_sb(const struct silofs_uber1k *uber1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_ltype ltype;

	uber1k_sb_uaddr(uber1k, &uaddr);
	height = uaddr_height(&uaddr);
	ltype = uaddr_ltype(&uaddr);
	if ((ltype != SILOFS_LTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad uber uaddr-sb: voff=%ld ltype=%d height=%d",
		        uaddr.voff, (int)ltype, (int)height);
		return -SILOFS_EBADUBER;
	}
	return 0;
}

static void
uber1k_uuid(const struct silofs_uber1k *uber1k, struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &uber1k->ub_uuid);
}

static void
uber1k_set_uuid(struct silofs_uber1k *uber1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&uber1k->ub_uuid, uuid);
}

static int uber1k_check(const struct silofs_uber1k *uber1k)
{
	int algo;
	int mode;
	int err;

	err = uber1k_check_base(uber1k);
	if (err) {
		return err;
	}
	err = uber1k_check_uaddr_sb(uber1k);
	if (err) {
		return err;
	}
	algo = uber1k_chiper_algo(uber1k);
	mode = uber1k_chiper_mode(uber1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static void
uber1k_hash(const struct silofs_uber1k *uber1k, struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &uber1k->ub_hash);
}

static void uber1k_set_hash(struct silofs_uber1k *uber1k,
                            const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&uber1k->ub_hash, hash);
}

static void uber1k_calc_hash(const struct silofs_uber1k *uber1k,
                             const struct silofs_mdigest *md,
                             struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_uber1k, ub_hash);

	silofs_sha3_256_of(md, uber1k, len, out_hash);
}

void silofs_uber1k_stamp(struct silofs_uber1k *uber1k,
                         const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	uber1k_calc_hash(uber1k, md, &hash);
	uber1k_set_hash(uber1k, &hash);
}

static int uber1k_check_hash(const struct silofs_uber1k *uber1k,
                             const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	uber1k_hash(uber1k, &hash[0]);
	uber1k_calc_hash(uber1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int uber1k_verify(const struct silofs_uber1k *uber1k,
                         const struct silofs_mdigest *md)
{
	int err;

	err = uber1k_check(uber1k);
	if (err) {
		return err;
	}
	err = uber1k_check_hash(uber1k, md);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_uber1k_verify(const struct silofs_uber1k *uber1k,
                         const struct silofs_mdigest *md)
{
	return uber1k_verify(uber1k, md);
}

void silofs_uber1k_xtoh(const struct silofs_uber1k *uber1k,
                        struct silofs_uber *uber)
{
	uber1k_sb_uaddr(uber1k, &uber->sb_ulink.uaddr);
	uber1k_sb_riv(uber1k, &uber->sb_ulink.riv);
	uber->flags = uber1k_flags(uber1k);
	uber1k_uuid(uber1k, &uber->uuid);
	uber1k_main_ivkey(uber1k, &uber->main_ivkey);
	uber1k_pvsegr(uber1k, &uber->pvsegr);
	uber->cipher_algo = (int32_t)uber1k_chiper_algo(uber1k);
	uber->cipher_mode = (int32_t)uber1k_chiper_mode(uber1k);
}

void silofs_uber1k_htox(struct silofs_uber1k *uber1k,
                        const struct silofs_uber *uber)
{
	silofs_uber1k_init(uber1k);
	uber1k_set_sb_uaddr(uber1k, &uber->sb_ulink.uaddr);
	uber1k_set_sb_riv(uber1k, &uber->sb_ulink.riv);
	uber1k_set_flags(uber1k, uber->flags);
	uber1k_set_uuid(uber1k, &uber->uuid);
	uber1k_set_main_ivkey(uber1k, &uber->main_ivkey);
	uber1k_set_pvsegr(uber1k, &uber->pvsegr);
	uber1k_set_cipher(uber1k, uber->cipher_algo, uber->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber_init(struct silofs_uber *uber)
{
	silofs_memzero(uber, sizeof(*uber));
	silofs_ulink_reset(&uber->sb_ulink);
	uber->flags = SILOFS_UBERF_NONE;
	uber->cipher_algo = SILOFS_CIPHER_AES256;
	uber->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_uber_fini(struct silofs_uber *uber)
{
	silofs_memffff(uber, sizeof(*uber));
}

void silofs_uber_assign(struct silofs_uber *uber,
                        const struct silofs_uber *other)
{
	silofs_uuid_assign(&uber->uuid, &other->uuid);
	silofs_ivkey_assign(&uber->main_ivkey, &other->main_ivkey);
	silofs_pvsegr_assign(&uber->pvsegr, &other->pvsegr);
	silofs_ulink_assign(&uber->sb_ulink, &other->sb_ulink);
	uber->flags = other->flags;
	uber->cipher_algo = other->cipher_algo;
	uber->cipher_mode = other->cipher_mode;
}

void silofs_uber_gen_uuid(struct silofs_uber *uber)
{
	silofs_uuid_generate(&uber->uuid);
}

void silofs_uber_set_ivkey(struct silofs_uber *uber,
                           const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&uber->main_ivkey, ivkey);
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

int silofs_uber_gen_ivkey(struct silofs_uber *uber,
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
	silofs_uber_set_ivkey(uber, &ivkey[0]);
	return 0;
}

void silofs_uber_pvsegr(const struct silofs_uber *uber,
                        struct silofs_pvsegr *out_pvsegr)
{
	silofs_pvsegr_assign(out_pvsegr, &uber->pvsegr);
}

void silofs_uber_set_pvsegr(struct silofs_uber *uber,
                            const struct silofs_pvsegr *pvsegr)
{
	silofs_pvsegr_assign(&uber->pvsegr, pvsegr);
}

void silofs_uber_sb_ulink(const struct silofs_uber *uber,
                          struct silofs_ulink *out_ulink)
{
	silofs_ulink_assign(out_ulink, &uber->sb_ulink);
}

void silofs_uber_set_sb_ulink(struct silofs_uber *uber,
                              const struct silofs_ulink *sb_ulink)
{
	silofs_ulink_assign(&uber->sb_ulink, sb_ulink);
}

void silofs_uber_volid(const struct silofs_uber *uber,
                       struct silofs_volid *out_volid)
{
	const struct silofs_uaddr *sb_uaddr = &uber->sb_ulink.uaddr;

	silofs_volid_assign(out_volid, &sb_uaddr->laddr.lsid.volid);
}

static void uber_uaddr_by_volid(const struct silofs_volid *volid,
                                struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const enum silofs_ltype ltype = SILOFS_LTYPE_UBER;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsid_setup(&lsid, volid, 0, ltype, height, ltype);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

void silofs_make_uber_uaddr(const struct silofs_volid *volid,
                            struct silofs_uaddr *out_uaddr)
{
	uber_uaddr_by_volid(volid, out_uaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int encrypt_uber1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_uber1k *uber1k_in,
                          struct silofs_uber1k *uber1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, uber1k_in, uber1k_out,
	                          sizeof(*uber1k_out));
}

static int decrypt_uber1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_uber1k *uber1k_in,
                          struct silofs_uber1k *uber1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, uber1k_in, uber1k_out,
	                          sizeof(*uber1k_out));
}

static int
uber_encode(const struct silofs_uber *uber,
            const struct silofs_mdigest *mdigest,
            const struct silofs_cipher *cipher,
            const struct silofs_ivkey *ivkey, struct silofs_uber1k *out_uber1k)
{
	struct silofs_uber1k uber1k;

	silofs_uber1k_htox(&uber1k, uber);
	silofs_uber1k_stamp(&uber1k, mdigest);
	return encrypt_uber1k(cipher, ivkey, &uber1k, out_uber1k);
}

static int
uber_decode(struct silofs_uber *uber, const struct silofs_mdigest *mdigest,
            const struct silofs_cipher *cipher,
            const struct silofs_ivkey *ivkey,
            const struct silofs_uber1k *uber1k_enc)
{
	struct silofs_uber1k uber1k = { .ub_magic = 1 };
	int err;

	err = decrypt_uber1k(cipher, ivkey, uber1k_enc, &uber1k);
	if (err) {
		return err;
	}
	err = uber1k_verify(&uber1k, mdigest);
	if (err) {
		return err;
	}
	silofs_uber1k_xtoh(&uber1k, uber);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_encode_uber(const struct silofs_env *env,
                       const struct silofs_uber *uber,
                       struct silofs_uber1k *out_uber1k)
{
	return uber_encode(uber, &env->mdigest, &env->uber_cipher,
	                   &env->uber_ivkey, out_uber1k);
}

int silofs_decode_uber(const struct silofs_env *env,
                       const struct silofs_uber1k *uber1k_enc,
                       struct silofs_uber *out_uber)
{
	return uber_decode(out_uber, &env->mdigest, &env->uber_cipher,
	                   &env->uber_ivkey, uber1k_enc);
}

static void calc_uber1k_caddr(const struct silofs_env *env,
                              const struct silofs_uber1k *uber1k,
                              struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = unconst(uber1k),
		.iov_len = sizeof(*uber1k),
	};

	silofs_calc_caddr_of(&iov, 1, SILOFS_CTYPE_UBER, &env->mdigest,
	                     out_caddr);
}

static int verify_uber1k_caddr(const struct silofs_env *env,
                               const struct silofs_uber1k *uber1k,
                               const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_uber1k_caddr(env, uber1k, &caddr2);
	return caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADUBER;
}

int silofs_calc_uber_caddr(const struct silofs_env *env,
                           const struct silofs_uber *uber,
                           struct silofs_caddr *out_caddr)
{
	struct silofs_uber1k uber1k_enc = {
		.ub_magic = 1,
	};
	int err;

	err = silofs_encode_uber(env, uber, &uber1k_enc);
	if (err) {
		log_err("failed to encode uber: err=%d", err);
		return err;
	}
	calc_uber1k_caddr(env, &uber1k_enc, out_caddr);
	return 0;
}

int silofs_save_uber(const struct silofs_env *env,
                     const struct silofs_uber *uber,
                     struct silofs_caddr *out_caddr)
{
	struct silofs_uber1k uber1k_enc = {
		.ub_magic = 1,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &uber1k_enc,
		.rov_len = sizeof(uber1k_enc),
	};
	struct silofs_caddr caddr;
	int err;

	err = silofs_encode_uber(env, uber, &uber1k_enc);
	if (err) {
		log_err("failed to encode uber: err=%d", err);
		return err;
	}
	calc_uber1k_caddr(env, &uber1k_enc, &caddr);
	err = silofs_repo_save_cobj(env->base.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save uber: err=%d", err);
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

int silofs_load_uber(const struct silofs_env *env,
                     const struct silofs_caddr *caddr,
                     struct silofs_uber *out_uber)
{
	struct silofs_uber1k uber1k_enc = { .ub_magic = 0 };
	struct silofs_rwvec rwvec = {
		.rwv_base = &uber1k_enc,
		.rwv_len = sizeof(uber1k_enc),
	};
	int err;

	err = silofs_repo_lookup_ref(env->base.repo, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
	err = silofs_repo_load_cobj(env->base.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load uber: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOUBER : err;
	}
	err = verify_uber1k_caddr(env, &uber1k_enc, caddr);
	if (err) {
		log_dbg("failed to verify uber: err=%d", err);
		return err;
	}
	err = silofs_decode_uber(env, &uber1k_enc, out_uber);
	if (err) {
		log_dbg("failed to decode uber: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_stat_uber(const struct silofs_env *env,
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
		log_err("failed to stat uber: err=%d", err);
		return err;
	}
	if (sz != SILOFS_UBER_SIZE) {
		log_warn("bad uber: size=%zu", sz);
		return -SILOFS_EBADUBER;
	}
	return 0;
}

int silofs_reload_uber(struct silofs_env *env,
                       const struct silofs_caddr *caddr,
                       struct silofs_uber *out_uber)
{
	int err;

	err = silofs_stat_uber(env, caddr);
	if (err) {
		return err;
	}
	err = silofs_load_uber(env, caddr, out_uber);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, out_uber);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_unlink_uber(const struct silofs_env *env,
                       const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink uber: err=%d", err);
		return err;
	}
	err = silofs_repo_remove_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}
