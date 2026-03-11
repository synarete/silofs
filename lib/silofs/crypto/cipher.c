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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <gcrypt.h>

#include <silofs/infra.h>
#include "gcry.h"
#include "mdigest.h"
#include "ivkey.h"
#include "cipher.h"

#define SILOFS_CIPHER_ALGO_DEFAULT SILOFS_CIPHER_AES256
#define SILOFS_CIPHER_MODE_DEFAULT SILOFS_CIPHER_MODE_GCM

static int check_cipher_algo(enum silofs_cipher_algo algo)
{
	int ret = 0;

	switch (algo) {
	case SILOFS_CIPHER_AES256:
		break;
	case SILOFS_CIPHER_NONE:
	default:
		silofs_log_warn("unsupported cipher-algo: %d", (int)algo);
		ret = -SILOFS_EOPNOTSUPP;
		break;
	}
	return ret;
}

static int check_cipher_mode(enum silofs_cipher_mode mode)
{
	int ret = 0;

	switch (mode) {
	case SILOFS_CIPHER_MODE_CBC:
	case SILOFS_CIPHER_MODE_GCM:
	case SILOFS_CIPHER_MODE_XTS:
		break;
	case SILOFS_CIPHER_MODE_NONE:
	default:
		silofs_log_warn("unsupported cipher-mode: %d", (int)mode);
		ret = -SILOFS_EOPNOTSUPP;
		break;
	}
	return ret;
}

int silofs_ciargs_check(const struct silofs_ciargs *ciargs)
{
	int err;

	err = check_cipher_algo(ciargs->algo);
	if (err) {
		return err;
	}
	err = check_cipher_mode(ciargs->mode);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_ciargs_setup(struct silofs_ciargs *ciargs,
                         enum silofs_cipher_algo algo,
                         enum silofs_cipher_mode mode)
{
	ciargs->algo = algo;
	ciargs->mode = mode;
}

void silofs_ciargs_assign(struct silofs_ciargs *ciargs,
                          const struct silofs_ciargs *other)
{
	silofs_ciargs_setup(ciargs, other->algo, other->mode);
}

void silofs_ciargs_reset(struct silofs_ciargs *ciargs)
{
	silofs_ciargs_assign(ciargs, silofs_ciargs_default());
}

bool silofs_ciargs_isequal(const struct silofs_ciargs *ciargs,
                           const struct silofs_ciargs *other)
{
	return (ciargs->algo == other->algo) && (ciargs->mode == other->mode);
}

static const struct silofs_ciargs s_ciargs_default = {
	.algo = SILOFS_CIPHER_ALGO_DEFAULT,
	.mode = SILOFS_CIPHER_MODE_DEFAULT,
};

const struct silofs_ciargs *silofs_ciargs_default(void)
{
	SILOFS_STATICASSERT_EQ(GCRY_CIPHER_AES256,
	                       (int)SILOFS_CIPHER_ALGO_DEFAULT);
	SILOFS_STATICASSERT_EQ(GCRY_CIPHER_MODE_GCM,
	                       (int)SILOFS_CIPHER_MODE_DEFAULT);

	return &s_ciargs_default;
}

static size_t
ciargs_keysize(const struct silofs_ciargs *ciargs, size_t keysize_want)
{
	size_t keysize;

	switch (ciargs->mode) {
	case SILOFS_CIPHER_MODE_CBC:
	case SILOFS_CIPHER_MODE_GCM:
		keysize = silofs_min(keysize_want, 32);
		break;
	case SILOFS_CIPHER_MODE_XTS:
		keysize = silofs_min(keysize_want, 64);
		break;
	case SILOFS_CIPHER_MODE_NONE:
	default:
		keysize = keysize_want;
		break;
	}
	return keysize;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
cipher_open(struct silofs_cipher_hd *ci_hd, const struct silofs_ciargs *ciargs)
{
	const unsigned int flags = 0; /* XXX GCRY_CIPHER_SECURE ? */
	gcry_error_t err;

	err = gcry_cipher_open(&ci_hd->ci_hd, (int)ciargs->algo,
	                       (int)ciargs->mode, flags);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_open");
	}
	silofs_ciargs_assign(&ci_hd->ci_args, ciargs);
	return 0;
}

static void cipher_close(struct silofs_cipher_hd *ci_hd)
{
	gcry_cipher_close(ci_hd->ci_hd);
	ci_hd->ci_hd = nullptr;
}

int silofs_cipher_init(struct silofs_cipher_hd *ci_hd)
{
	struct silofs_ciargs ciargs;

	silofs_ciargs_reset(&ciargs);
	return cipher_open(ci_hd, &ciargs);
}

static bool cipher_has_args(const struct silofs_cipher_hd *ci_hd,
                            const struct silofs_ciargs *ciargs)
{
	return silofs_ciargs_isequal(&ci_hd->ci_args, ciargs);
}

int silofs_cipher_reinit(struct silofs_cipher_hd *ci_hd,
                         const struct silofs_ciargs *ciargs)
{
	int err;

	err = silofs_ciargs_check(ciargs);
	if (err) {
		return err;
	}
	if (cipher_has_args(ci_hd, ciargs)) {
		return 0; /* no-op */
	}
	cipher_close(ci_hd);
	err = cipher_open(ci_hd, ciargs);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_cipher_fini(struct silofs_cipher_hd *ci_hd)
{
	if (ci_hd->ci_hd != nullptr) {
		cipher_close(ci_hd);
	}
}

int silofs_cipher_check(const struct silofs_cipher_hd *ci_hd,
                        const struct silofs_ciargs *ciargs)
{
	return cipher_has_args(ci_hd, ciargs) ? 0 : -SILOFS_EOPNOTSUPP;
}

static int cipher_prepare(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey *civkey)
{
	const struct silofs_civ *iv   = &civkey->iv;
	const struct silofs_ckey *key = &civkey->key;
	size_t blklen, keysize;
	gcry_error_t err;

	blklen = gcry_cipher_get_algo_blklen((int)ci_hd->ci_args.algo);
	if (blklen > sizeof(iv->iv)) {
		silofs_log_warn("bad blklen: algo=%d blklen=%zu",
		                (int)ci_hd->ci_args.algo, blklen);
		return -SILOFS_EINVAL;
	}
	err = gcry_cipher_reset(ci_hd->ci_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_reset");
	}
	keysize = ciargs_keysize(&ci_hd->ci_args, sizeof(key->key));
	err     = gcry_cipher_setkey(ci_hd->ci_hd, key->key, keysize);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_setkey");
	}
	err = gcry_cipher_setiv(ci_hd->ci_hd, iv->iv, blklen);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_setiv");
	}
	return 0;
}

static int cipher_encrypt(const struct silofs_cipher_hd *ci_hd,
                          const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_encrypt(ci_hd->ci_hd, out_dat, dat_len, in_dat,
	                          dat_len);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_encrypt");
	}
	err = gcry_cipher_final(ci_hd->ci_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_final");
	}
	return 0;
}

static int cipher_decrypt(const struct silofs_cipher_hd *ci_hd,
                          const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_decrypt(ci_hd->ci_hd, out_dat, dat_len, in_dat,
	                          dat_len);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_decrypt");
	}
	err = gcry_cipher_final(ci_hd->ci_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_cipher_final");
	}
	return 0;
}

int silofs_encrypt_buf(const struct silofs_cipher_hd *ci_hd,
                       const struct silofs_civkey *civkey, const void *in_dat,
                       void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci_hd, civkey);
	if (err) {
		return err;
	}
	err = cipher_encrypt(ci_hd, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_decrypt_buf(const struct silofs_cipher_hd *ci_hd,
                       const struct silofs_civkey *civkey, const void *in_dat,
                       void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci_hd, civkey);
	if (err) {
		return err;
	}
	err = cipher_decrypt(ci_hd, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}
