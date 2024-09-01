/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/errors.h>
#include <silofs/crypt.h>
#include <gcrypt.h>


int silofs_check_cipher_args(int algo, int mode)
{
	if (algo != GCRY_CIPHER_AES256) {
		silofs_log_warn("unsupported chipher-algo: %d", algo);
		return -SILOFS_EOPNOTSUPP;
	}
	if ((mode != GCRY_CIPHER_MODE_GCM) &&
	    (mode != GCRY_CIPHER_MODE_CBC) &&
	    (mode != GCRY_CIPHER_MODE_XTS)) {
		silofs_log_warn("unsupported chipher-mode: %d", mode);
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int cipher_open(struct silofs_cipher *ci, int algo, int mode)
{
	const unsigned int flags = 0; /* XXX GCRY_CIPHER_SECURE ? */
	gcry_error_t err;

	err = gcry_cipher_open(&ci->cipher_hd, algo, mode, flags);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_open");
	}
	ci->cipher_algo = algo;
	ci->cipher_mode = mode;
	return 0;
}

static void cipher_close(struct silofs_cipher *ci)
{
	gcry_cipher_close(ci->cipher_hd);
	ci->cipher_hd = NULL;
	ci->cipher_algo = GCRY_CIPHER_NONE;
	ci->cipher_mode = GCRY_CIPHER_MODE_NONE;
}

int silofs_cipher_init(struct silofs_cipher *ci)
{
	const int algo = GCRY_CIPHER_AES256;
	const int mode = GCRY_CIPHER_MODE_GCM;
	int err;

	STATICASSERT_EQ(GCRY_CIPHER_AES256, (int)SILOFS_CIPHER_ALGO_DEFAULT);
	STATICASSERT_EQ(GCRY_CIPHER_MODE_GCM, (int)SILOFS_CIPHER_MODE_DEFAULT);

	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	err = cipher_open(ci, algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_cipher_reinit(struct silofs_cipher *ci, int algo, int mode)
{
	int err;

	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
	}
	if ((ci->cipher_algo == algo) && (ci->cipher_mode == mode)) {
		return 0; /* no-op */
	}
	cipher_close(ci);
	err = cipher_open(ci, algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_cipher_fini(struct silofs_cipher *ci)
{
	if (ci->cipher_hd != NULL) {
		cipher_close(ci);
	}
}

static int cipher_prepare(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey)
{
	const struct silofs_iv *iv = &ivkey->iv;
	const struct silofs_key *key = &ivkey->key;
	size_t blklen;
	gcry_error_t err;

	blklen = gcry_cipher_get_algo_blklen(ci->cipher_algo);
	if (blklen > sizeof(iv->iv)) {
		silofs_log_warn("bad blklen: %lu", blklen);
		return -SILOFS_EINVAL;
	}
	err = gcry_cipher_reset(ci->cipher_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_reset");
	}
	err = gcry_cipher_setkey(ci->cipher_hd, key->key, sizeof(key->key));
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_setkey");
	}
	err = gcry_cipher_setiv(ci->cipher_hd, iv->iv, blklen);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_setiv");
	}
	return 0;
}

static int cipher_encrypt(const struct silofs_cipher *ci,
                          const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_encrypt(ci->cipher_hd, out_dat,
	                          dat_len, in_dat, dat_len);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_encrypt");
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_final");
	}
	return 0;
}

static int cipher_decrypt(const struct silofs_cipher *ci,
                          const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_decrypt(ci->cipher_hd, out_dat,
	                          dat_len, in_dat, dat_len);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_decrypt");
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_final");
	}
	return 0;
}

int silofs_encrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey,
                       const void *in_dat, void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci, ivkey);
	if (err) {
		return err;
	}
	err = cipher_encrypt(ci, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_decrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey,
                       const void *in_dat, void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci, ivkey);
	if (err) {
		return err;
	}
	err = cipher_decrypt(ci, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int derive_iv(const struct silofs_mdigest *md,
                     const struct silofs_password *pw,
                     const struct silofs_kdf_desc *kdf,
                     struct silofs_iv *out_iv)
{
	struct silofs_hash256 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_256) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_256_of(md, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass, pw->passlen,
	                           (int)kdf->kd_algo, /* GCRY_KDF_PBKDF2 */
	                           (int)kdf->kd_subalgo, /* GCRY_MD_SHA256 */
	                           salt.hash, sizeof(salt.hash),
	                           kdf->kd_iterations, /* 4096 */
	                           sizeof(out_iv->iv), out_iv->iv);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}

static int derive_key(const struct silofs_mdigest *md,
                      const struct silofs_password *pw,
                      const struct silofs_kdf_desc *kdf,
                      struct silofs_key *out_key)
{
	struct silofs_hash512 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_512) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_512_of(md, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass, pw->passlen,
	                           (int)kdf->kd_algo, /* GCRY_KDF_SCRYPT */
	                           (int)kdf->kd_subalgo, /* 8 */
	                           salt.hash, sizeof(salt.hash),
	                           kdf->kd_iterations, /* 1024 */
	                           sizeof(out_key->key), out_key->key);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}

static int silofs_derive_ivkey(const struct silofs_mdigest *md,
                               const struct silofs_password *pw,
                               const struct silofs_kdf_pair *kdf,
                               struct silofs_ivkey *out_ivkey)
{
	int err;

	silofs_memzero(out_ivkey, sizeof(*out_ivkey));
	err = silofs_password_check(pw);
	if (err) {
		goto out;
	}
	err = derive_iv(md, pw, &kdf->kdf_iv, &out_ivkey->iv);
	if (err) {
		goto out;
	}
	err = derive_key(md, pw, &kdf->kdf_key, &out_ivkey->key);
	if (err) {
		goto out;
	}
out:
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_encdec_args s_boot_ed_args = {
	.kdf = {
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
	},
	.cipher_algo = SILOFS_CIPHER_ALGO_DEFAULT,
	.cipher_mode = SILOFS_CIPHER_MODE_DEFAULT,
};

int silofs_derive_boot_ivkey(const struct silofs_mdigest *md,
                             const struct silofs_password *pw,
                             struct silofs_ivkey *out_ivkey)
{
	return silofs_derive_ivkey(md, pw, &s_boot_ed_args.kdf, out_ivkey);
}
