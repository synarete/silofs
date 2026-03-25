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
#ifndef SILOFS_CRYPTO_H_
#define SILOFS_CRYPTO_H_

#include <stdlib.h>
#include <stdint.h>
#include <gcrypt.h>

#include <silofs/infra.h>
#include <silofs/ondisk.h>
#include <silofs/types.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* passwd */

int silofs_password_setup(struct silofs_password *pw, const char *pass);

int silofs_password_assign(struct silofs_password       *pw,
			   const struct silofs_password *other);

void silofs_password_reset(struct silofs_password *pw);

int silofs_password_recheck(const struct silofs_password *pw);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* ivkey */

/* encryption IV-key pair */
struct silofs_civkey {
	struct silofs_ckey key;
	struct silofs_civ  iv;
};

void silofs_civ_reset(struct silofs_civ *iv);

void silofs_civ_assign(struct silofs_civ       *iv,
		       const struct silofs_civ *iv_other);

void silofs_civ_mkrand(struct silofs_civ *iv);

bool silofs_civ_isequal(const struct silofs_civ *iv,
			const struct silofs_civ *iv_other);

long silofs_civ_compare(const struct silofs_civ *iv,
			const struct silofs_civ *iv_other);

void silofs_civ_xor_with(struct silofs_civ *iv, const void *buf, size_t len);

void silofs_civ_xor_with1(struct silofs_civ *iv, const struct silofs_civ *iv1);

void silofs_civ_xor_with2(struct silofs_civ *iv, const struct silofs_civ *iv1,
			  const struct silofs_civ *iv2);

void silofs_gen_random_iv(struct silofs_civ *iv);

void silofs_gen_random_ivs(struct silofs_civ *ivs, size_t nivs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ckey_reset(struct silofs_ckey *key);

void silofs_ckey_assign(struct silofs_ckey       *key,
			const struct silofs_ckey *other);

bool silofs_ckey_isequal(const struct silofs_ckey *key,
			 const struct silofs_ckey *other);

void silofs_ckey_mkrand(struct silofs_ckey *key);

void silofs_ckey_xor_with(struct silofs_ckey *key, const void *buf,
			  size_t len);

void silofs_ckey_xor_with2(struct silofs_ckey       *key,
			   const struct silofs_ckey *key1);

void silofs_generate_keys(struct silofs_ckey *keys, size_t nkeys);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_civkey_init(struct silofs_civkey *civkey);

void silofs_civkey_reset(struct silofs_civkey *civkey);

void silofs_civkey_mkrand(struct silofs_civkey *civkey);

void silofs_civkey_setup(struct silofs_civkey     *civkey,
			 const struct silofs_ckey *key,
			 const struct silofs_civ  *iv);

void silofs_civkey_assign(struct silofs_civkey       *civkey,
			  const struct silofs_civkey *other);

bool silofs_civkey_isequal(const struct silofs_civkey *civkey,
			   const struct silofs_civkey *other);

void silofs_civkey_xor_with(struct silofs_civkey       *civkey,
			    const struct silofs_civkey *other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* mdigest */

struct iovec;
struct silofs_hash256;
struct silofs_hash512;

struct silofs_mdigest_hd {
	gcry_md_hd_t md_hd;
	int16_t      md_algos[7];
	int16_t      md_nalgos;
};

int silofs_mdigest_init(struct silofs_mdigest_hd *md_hd);

void silofs_mdigest_fini(struct silofs_mdigest_hd *md_hd);

void silofs_sha256_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
		      size_t bsz, struct silofs_hash256 *out_hash);

void silofs_sha256_ofv(const struct silofs_mdigest_hd *md_hd,
		       const struct iovec *iov, size_t cnt,
		       struct silofs_hash256 *out_hash);

void silofs_sha3_256_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
			size_t bsz, struct silofs_hash256 *out_hash);

void silofs_sha3_256_ofv(const struct silofs_mdigest_hd *md_hd,
			 const struct iovec *iov, size_t cnt,
			 struct silofs_hash256 *out_hash);

void silofs_sha3_512_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
			size_t bsz, struct silofs_hash512 *out_hash);

void silofs_crc32_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
		     size_t bsz, uint32_t *out_crc32);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* kdf */

struct silofs_kdf_desc {
	uint32_t kd_iterations;
	uint32_t kd_algo;
	uint16_t kd_subalgo;
	uint16_t kd_salt_md;
	uint32_t kd_reserved;
};

struct silofs_kdf_descs {
	struct silofs_kdf_desc kdf_iv;
	struct silofs_kdf_desc kdf_key;
};

int silofs_derive_civkey(const struct silofs_mdigest_hd *md_hd,
			 const struct silofs_password   *pw,
			 const struct silofs_kdf_descs  *kdf,
			 struct silofs_civkey           *out_civkey);

int silofs_derive_hmac_key(const struct silofs_mdigest_hd *md_hd,
			   const struct silofs_password   *pw,
			   const struct silofs_kdf_desc   *kdf,
			   struct silofs_ckey             *out_key);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* hmac */

/* wrapper over libgcrypt mac handle */
struct silofs_hmac_hd {
	gcry_mac_hd_t hm_hd;
	int           hm_algo;
};

bool silofs_mac_isequal(const struct silofs_mac *mac,
			const struct silofs_mac *other);

int silofs_hmac_init(struct silofs_hmac_hd *hmac_hd);

void silofs_hmac_fini(struct silofs_hmac_hd *hmac_hd);

int silofs_hmac_calc(struct silofs_hmac_hd    *hmac_hd,
		     const struct silofs_ckey *key, const void *dat,
		     size_t dsz, struct silofs_mac *out_mac);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* cipher */

/* cipher's operation arguments */
struct silofs_ciargs {
	enum silofs_cipher_algo algo;
	enum silofs_cipher_mode mode;
};

/* wrapper over libgcrypt cipher handle */
struct silofs_cipher_hd {
	gcry_cipher_hd_t     ci_hd;
	struct silofs_ciargs ci_args;
};

const struct silofs_ciargs *silofs_ciargs_default(void);

void silofs_ciargs_setup(struct silofs_ciargs   *ciargs,
			 enum silofs_cipher_algo algo,
			 enum silofs_cipher_mode mode);

void silofs_ciargs_assign(struct silofs_ciargs       *ciargs,
			  const struct silofs_ciargs *other);

void silofs_ciargs_reset(struct silofs_ciargs *ciargs);

bool silofs_ciargs_isequal(const struct silofs_ciargs *ciargs,
			   const struct silofs_ciargs *other);

int silofs_ciargs_check(const struct silofs_ciargs *ciargs);

int silofs_cipher_init(struct silofs_cipher_hd *ci_hd);

int silofs_cipher_reinit(struct silofs_cipher_hd    *ci_hd,
			 const struct silofs_ciargs *ciargs);

void silofs_cipher_fini(struct silofs_cipher_hd *ci_hd);

int silofs_cipher_check(const struct silofs_cipher_hd *ci_hd,
			const struct silofs_ciargs    *ciargs);

int silofs_encrypt_buf(const struct silofs_cipher_hd *ci_hd,
		       const struct silofs_civkey *civkey, const void *in_dat,
		       void *out_dat, size_t dat_len);

int silofs_decrypt_buf(const struct silofs_cipher_hd *ci_hd,
		       const struct silofs_civkey *civkey, const void *in_dat,
		       void *out_dat, size_t dat_len);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* prand */

/* prng state input */
struct silofs_prndstate {
	uint8_t s[32];
};

/* pseudo random generator using libgcrypt SHA3 */
struct silofs_prandgen {
	struct silofs_prndstate  state[16];
	uint64_t                 prandom[32];
	uint64_t                 icount;
	uint64_t                 xcount;
	uint32_t                 cycle;
	uint32_t                 slot;
	struct silofs_mdigest_hd md_hd;
};

int silofs_prandgen_init(struct silofs_prandgen *prng);

void silofs_prandgen_fini(struct silofs_prandgen *prng);

void silofs_prandgen_feed(struct silofs_prandgen *prng, const void *p,
			  size_t n);

void silofs_prandgen_take(struct silofs_prandgen *prng, void *p, size_t n);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* gcry */

const char *silofs_gcrypt_version(void);

int silofs_init_gcrypt(bool with_fips);

int silofs_gcrypt_status_(gcry_error_t gcry_err, const char *fn,
			  const char *file, int line);

#define silofs_gcrypt_status(gcry_err_, fn_) \
	silofs_gcrypt_status_(gcry_err_, fn_, SILOFS_FL_LN_)

void silofs_gcrypt_random(void *ptr, size_t len);

#endif /* SILOFS_CRYPTO_H_ */
