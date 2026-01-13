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
#include <silofs/ondisk.h>
#include <silofs/errors.h>
#include "mdigest.h"
#include "gcry.h"
#include "kdf.h"

static int
derive_key(const struct silofs_mdigest_hd *md_hd,
           const struct silofs_password *pw, const struct silofs_kdf_desc *kdf,
           struct silofs_ckey *out_key)
{
	struct silofs_hash512 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_512) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_512_of(md_hd, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass,             //
	                           pw->passlen,          //
	                           (int)kdf->kd_algo,    //
	                           (int)kdf->kd_subalgo, //
	                           salt.hash,            //
	                           sizeof(salt.hash),    //
	                           kdf->kd_iterations,   //
	                           sizeof(out_key->key), //
	                           out_key->key);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}

static int derive_iv(const struct silofs_mdigest_hd *md_hd, //
                     const struct silofs_password *pw,      //
                     const struct silofs_kdf_desc *kdf,     //
                     struct silofs_civ *out_iv)
{
	struct silofs_hash256 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_256) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_256_of(md_hd, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass,             //
	                           pw->passlen,          //
	                           (int)kdf->kd_algo,    //
	                           (int)kdf->kd_subalgo, //
	                           salt.hash,            //
	                           sizeof(salt.hash),    //
	                           kdf->kd_iterations,   //
	                           sizeof(out_iv->iv),   //
	                           out_iv->iv);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}

static int check_passlen(size_t len)
{
	int ret = 0;

	if ((len < SILOFS_PASSWORD_MIN) || (len > SILOFS_PASSWORD_MAX)) {
		ret = -SILOFS_EILLPASS;
	}
	return ret;
}

static int check_password(const struct silofs_password *pw)
{
	return check_passlen(pw->passlen);
}

int silofs_derive_civkey(const struct silofs_mdigest_hd *md_hd,
                         const struct silofs_password *pw,
                         const struct silofs_kdf_descs *kdf,
                         struct silofs_civkey *out_civkey)
{
	int err;

	silofs_civkey_reset(out_civkey);
	err = check_password(pw);
	if (err) {
		return err;
	}
	err = derive_iv(md_hd, pw, &kdf->kdf_iv, &out_civkey->iv);
	if (err) {
		return err;
	}
	err = derive_key(md_hd, pw, &kdf->kdf_key, &out_civkey->key);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_derive_hmac_key(const struct silofs_mdigest_hd *md_hd,
                           const struct silofs_password *pw,
                           const struct silofs_kdf_desc *kdf,
                           struct silofs_ckey *out_key)
{
	struct silofs_hash256 salt;
	gpg_error_t gcry_err;
	int err;

	err = check_password(pw);
	if (err) {
		return err;
	}
	if (kdf->kd_salt_md != SILOFS_MD_SHA3_256) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_256_of(md_hd, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass,             //
	                           pw->passlen,          //
	                           (int)kdf->kd_algo,
	                           (int)kdf->kd_subalgo, //
	                           salt.hash,            //
	                           sizeof(salt.hash),    //
	                           kdf->kd_iterations,   //
	                           sizeof(out_key->key), //
	                           out_key->key);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}
