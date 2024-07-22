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
#include <silofs/vol.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>


#define SILOFS_SECMEM_SIZE      (64L * SILOFS_KILO)

#define log_gcrypt_err(fn, err) \
	do { silofs_log_error("%s: %s", fn, gcry_strerror(err)); } while (0)


static int gcrypt_err(gcry_error_t gcry_err)
{
	const int err = (int)gcry_err;

	return (err > 0) ? -err : err;
}

int silofs_init_gcrypt(void)
{
	gcry_error_t err;
	enum gcry_ctl_cmds cmd;
	const char *version;
	const char *expected_version = GCRYPT_VERSION;

	version = gcry_check_version(expected_version);
	if (!version) {
		log_warn("libgcrypt version != %s", expected_version);
		return -1;
	}
	cmd = GCRYCTL_SUSPEND_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INIT_SECMEM;
	err = gcry_control(cmd, SILOFS_SECMEM_SIZE, 0);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_RESUME_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INITIALIZATION_FINISHED;
	gcry_control(cmd, 0);
	if (err) {
		goto out_control_err;
	}
	return 0;

out_control_err:
	log_gcrypt_err("gcry_control", err);
	return gcrypt_err(err);
}

const char *silofs_gcrypt_version(void)
{
	return GCRYPT_VERSION;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mdigest_init(struct silofs_mdigest *md)
{
	int algo;
	gcry_error_t err;
	const int algos[] = {
		GCRY_MD_MD5,
		GCRY_MD_CRC32,
		GCRY_MD_CRC32_RFC1510,
		GCRY_MD_CRC24_RFC2440,
		GCRY_MD_SHA256,
		GCRY_MD_SHA3_256,
		GCRY_MD_SHA3_512,
		GCRY_MD_BLAKE2S_128,
	};

	err = gcry_md_open(&md->md_hd, 0, 0 /* GCRY_MD_FLAG_SECURE */);
	if (err) {
		log_gcrypt_err("gcry_md_open", err);
		return gcrypt_err(err);
	}
	for (size_t i = 0; i < ARRAY_SIZE(algos); ++i) {
		algo = algos[i];
		err = gcry_md_enable(md->md_hd, algo);
		if (err) {
			log_gcrypt_err("gcry_md_enable", err);
			return gcrypt_err(err);
		}
	}
	return 0;
}

void silofs_mdigest_fini(struct silofs_mdigest *md)
{
	if (md->md_hd != NULL) {
		gcry_md_close(md->md_hd);
		md->md_hd = NULL;
	}
}

static void mdigest_calc_buf(const struct silofs_mdigest *md,
                             const void *buf, size_t bsz)
{
	gcry_md_reset(md->md_hd);
	gcry_md_write(md->md_hd, buf, bsz);
	gcry_md_final(md->md_hd);
}

static void mdigest_calc_iov(const struct silofs_mdigest *md,
                             const struct iovec *iovs, size_t cnt)
{
	const struct iovec *iov;

	gcry_md_reset(md->md_hd);
	for (size_t i = 0; i < cnt; ++i) {
		iov = &iovs[i];
		if (iov->iov_base && iov->iov_len) {
			gcry_md_write(md->md_hd, iov->iov_base, iov->iov_len);
		}
	}
	gcry_md_final(md->md_hd);
}

static void mdigest_read_hval(const struct silofs_mdigest *md, int algo,
                              size_t hash_len, void *out_hash_buf)
{
	const void *hval;

	hval = gcry_md_read(md->md_hd, algo);
	memcpy(out_hash_buf, hval, hash_len);
}

static void mdigest_calc(const struct silofs_mdigest *md, int algo,
                         const void *buf, size_t bsz, size_t hash_len,
                         void *out_hash_buf)
{
	mdigest_calc_buf(md, buf, bsz);
	mdigest_read_hval(md, algo, hash_len, out_hash_buf);
}

static void mdigest_vcalc(const struct silofs_mdigest *md, int algo,
                          const struct iovec *iovs, size_t cnt,
                          size_t hash_len, void *out_hash_buf)
{
	mdigest_calc_iov(md, iovs, cnt);
	mdigest_read_hval(md, algo, hash_len, out_hash_buf);
}

static void require_algo_dlen(int algo, size_t hlen)
{
	const size_t dlen = gcry_md_get_algo_dlen(algo);

	if (dlen != hlen) {
		silofs_panic("algo-dlen mismatch: "
		             "algo=%d dlen=%lu hlen=%lu", algo, dlen, hlen);
	}
}

void silofs_blake2s128_of(const struct silofs_mdigest *md,
                          const void *buf, size_t bsz,
                          struct silofs_hash128 *out_hash)
{
	const int algo = GCRY_MD_BLAKE2S_128;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void silofs_sha256_of(const struct silofs_mdigest *md,
                      const void *buf, size_t bsz,
                      struct silofs_hash256 *out_hash)
{
	const int algo = GCRY_MD_SHA256;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void silofs_sha256_ofv(const struct silofs_mdigest *md,
                       const struct iovec *iov, size_t cnt,
                       struct silofs_hash256 *out_hash)
{
	const int algo = GCRY_MD_SHA256;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_vcalc(md, algo, iov, cnt, hlen, out_hash->hash);
}

void silofs_sha3_256_of(const struct silofs_mdigest *md,
                        const void *buf, size_t bsz,
                        struct silofs_hash256 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int algo = GCRY_MD_SHA3_256;

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void silofs_sha3_512_of(const struct silofs_mdigest *md,
                        const void *buf, size_t bsz,
                        struct silofs_hash512 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int algo = GCRY_MD_SHA3_512;

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

static uint32_t digest_to_uint32(const uint8_t *digest)
{
	const uint32_t d0 = digest[0];
	const uint32_t d1 = digest[1];
	const uint32_t d2 = digest[2];
	const uint32_t d3 = digest[3];

	return (d0 << 24) | (d1 << 16) | (d2 << 8) << d3;
}

void silofs_crc32_of(const struct silofs_mdigest *md,
                     const void *buf, size_t bsz, uint32_t *out_crc32)
{
	const void *ptr;
	const int algo = GCRY_MD_CRC32;
	const size_t hlen = sizeof(*out_crc32);

	require_algo_dlen(algo, hlen);

	gcry_md_reset(md->md_hd);
	gcry_md_write(md->md_hd, buf, bsz);
	gcry_md_final(md->md_hd);
	ptr = gcry_md_read(md->md_hd, algo);

	*out_crc32 = digest_to_uint32(ptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_cipher_init(struct silofs_cipher *ci)
{
	gcry_error_t err;
	const int algo = GCRY_CIPHER_AES256;
	const int mode = GCRY_CIPHER_MODE_GCM;
	const unsigned int flags = 0; /* XXX GCRY_CIPHER_SECURE ? */

	err = gcry_cipher_open(&ci->cipher_hd, algo, mode, flags);
	if (err) {
		log_gcrypt_err("gcry_cipher_open", err);
		return gcrypt_err(err);
	}
	return 0;
}

void silofs_cipher_fini(struct silofs_cipher *ci)
{
	if (ci->cipher_hd != NULL) {
		gcry_cipher_close(ci->cipher_hd);
		ci->cipher_hd = NULL;
	}
}

static int chiper_verify(const struct silofs_cipher *ci,
                         const struct silofs_ivkey *ivkey)
{
	silofs_unused(ci);
	if (ivkey->algo != GCRY_CIPHER_AES256) {
		log_warn("unsupported chipher-algo: %d", ivkey->algo);
		return -SILOFS_EOPNOTSUPP;
	}
	if ((ivkey->mode != GCRY_CIPHER_MODE_GCM) &&
	    (ivkey->mode != GCRY_CIPHER_MODE_CBC) &&
	    (ivkey->mode != GCRY_CIPHER_MODE_XTS)) {
		log_warn("unsupported chipher-mode: %d", ivkey->mode);
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int cipher_prepare(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey)
{
	size_t blklen;
	gcry_error_t err;
	const struct silofs_iv *iv = &ivkey->iv;
	const struct silofs_key *key = &ivkey->key;

	blklen = gcry_cipher_get_algo_blklen((int)ivkey->algo);
	if (blklen > sizeof(iv->iv)) {
		log_warn("bad blklen: %lu", blklen);
		return -SILOFS_EINVAL;
	}
	err = gcry_cipher_reset(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_reset", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_setkey(ci->cipher_hd, key->key, sizeof(key->key));
	if (err) {
		log_gcrypt_err("gcry_cipher_setkey", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_setiv(ci->cipher_hd, iv->iv, blklen);
	if (err) {
		log_gcrypt_err("gcry_cipher_setiv", err);
		return gcrypt_err(err);
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
		log_gcrypt_err("gcry_cipher_encrypt", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_final", err);
		return gcrypt_err(err);
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
		log_gcrypt_err("gcry_cipher_decrypt", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_final", err);
		return gcrypt_err(err);
	}
	return 0;
}

int silofs_encrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey,
                       const void *in_dat, void *out_dat, size_t dat_len)
{
	int err;

	err = chiper_verify(ci, ivkey);
	if (err) {
		return err;
	}
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

	err = chiper_verify(ci, ivkey);
	if (err) {
		return err;
	}
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void password_setup(struct silofs_password *pp,
                           const void *pass, size_t passlen)
{
	silofs_memzero(pp, sizeof(*pp));
	if (passlen > 0) {
		memcpy(pp->pass, pass, passlen);
	}
	pp->passlen = passlen;
}

int silofs_password_setup(struct silofs_password *pp, const void *pass)
{
	const size_t passlen = silofs_str_length(pass);

	if (passlen >= sizeof(pp->pass)) {
		return -SILOFS_EINVAL;
	}
	password_setup(pp, pass, passlen);
	return 0;
}

void silofs_password_reset(struct silofs_password *pp)
{
	silofs_memzero(pp, sizeof(*pp));
	pp->passlen = 0;
}

static int password_check(const struct silofs_password *pp)
{
	if (!pp->passlen || (pp->passlen > sizeof(pp->pass))) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int derive_iv(const struct silofs_kdf_desc *kdf,
                     const struct silofs_password *pp,
                     const struct silofs_mdigest *md,
                     struct silofs_iv *out_iv)
{
	struct silofs_hash256 salt;
	gpg_error_t gcry_err;
	int ret = 0;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_256) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_256_of(md, pp->pass, pp->passlen, &salt);

	gcry_err = gcry_kdf_derive(pp->pass, pp->passlen,
	                           (int)kdf->kd_algo, /* GCRY_KDF_PBKDF2 */
	                           (int)kdf->kd_subalgo, /* GCRY_MD_SHA256 */
	                           salt.hash, sizeof(salt.hash),
	                           kdf->kd_iterations, /* 4096 */
	                           sizeof(out_iv->iv), out_iv->iv);
	if (gcry_err) {
		log_gcrypt_err("gcry_kdf_derive", gcry_err);
		ret = gcrypt_err(gcry_err);
	}
	return ret;
}

static int derive_key(const struct silofs_kdf_desc *kdf,
                      const struct silofs_password *pp,
                      const struct silofs_mdigest *md,
                      struct silofs_key *out_key)
{
	struct silofs_hash512 salt;
	gpg_error_t gcry_err;
	int ret = 0;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_512) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_512_of(md, pp->pass, pp->passlen, &salt);

	gcry_err = gcry_kdf_derive(pp->pass, pp->passlen,
	                           (int)kdf->kd_algo, /* GCRY_KDF_SCRYPT */
	                           (int)kdf->kd_subalgo, /* 8 */
	                           salt.hash, sizeof(salt.hash),
	                           kdf->kd_iterations, /* 1024 */
	                           sizeof(out_key->key), out_key->key);
	if (gcry_err) {
		log_gcrypt_err("gcry_kdf_derive", gcry_err);
		ret = gcrypt_err(gcry_err);
	}
	return ret;
}

int silofs_derive_ivkey(const struct silofs_cipher_args *cip_args,
                        const struct silofs_password *pp,
                        const struct silofs_mdigest *md,
                        struct silofs_ivkey *ivkey)
{
	int err;

	err = password_check(pp);
	if (err) {
		goto out;
	}
	err = derive_iv(&cip_args->kdf.kdf_iv, pp, md, &ivkey->iv);
	if (err) {
		goto out;
	}
	err = derive_key(&cip_args->kdf.kdf_key, pp, md, &ivkey->key);
	if (err) {
		goto out;
	}
	ivkey->algo = cip_args->cipher_algo;
	ivkey->mode = cip_args->cipher_mode;
out:
	if (err) {
		silofs_memzero(ivkey, sizeof(*ivkey));
	}
	return err;
}
