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
#include <silofs/errors.h>
#include "mdigest.h"
#include "gcry.h"
#include "kdf.h"

/*
 * TODO-0061: Use ARGON2 KDF
 *
 * ARGON2 is considered stronger (GPU-resistant) then PBKDF2 (see [1]) but
 * requires extra wrapping over libgcrypt APIs. Use it.
 *
 * [1] https://fedoraproject.org/wiki/Changes/ \
 *       RemoveFipsModeSetup#Context_information_on_FIPS
 */
static const struct silofs_kdf_descs s_kdf_descs_default = {
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
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
derive_iv(const struct silofs_mdigest *md, const struct silofs_password *pw,
          const struct silofs_kdf_desc *kdf, struct silofs_civ *out_iv)
{
	struct silofs_hash256 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_256) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_256_of(md, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass, pw->passlen, (int)kdf->kd_algo,
	                           (int)kdf->kd_subalgo, salt.hash,
	                           sizeof(salt.hash), kdf->kd_iterations,
	                           sizeof(out_iv->iv), out_iv->iv);
	return silofs_gcrypt_status(gcry_err, "gcry_kdf_derive");
}

static int
derive_key(const struct silofs_mdigest *md, const struct silofs_password *pw,
           const struct silofs_kdf_desc *kdf, struct silofs_ckey *out_key)
{
	struct silofs_hash512 salt;
	gpg_error_t gcry_err;

	if (kdf->kd_salt_md != SILOFS_MD_SHA3_512) {
		return -SILOFS_EOPNOTSUPP;
	}
	silofs_sha3_512_of(md, pw->pass, pw->passlen, &salt);
	gcry_err = gcry_kdf_derive(pw->pass, pw->passlen, (int)kdf->kd_algo,
	                           (int)kdf->kd_subalgo, salt.hash,
	                           sizeof(salt.hash), kdf->kd_iterations,
	                           sizeof(out_key->key), out_key->key);
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

static int derive_civkey(const struct silofs_mdigest *md,
                         const struct silofs_password *pw,
                         const struct silofs_kdf_descs *kdf,
                         struct silofs_civkey *out_civkey)
{
	int err;

	silofs_civkey_reset(out_civkey);
	err = check_passlen(pw->passlen);
	if (err) {
		return err;
	}
	err = derive_iv(md, pw, &kdf->kdf_iv, &out_civkey->iv);
	if (err) {
		return err;
	}
	err = derive_key(md, pw, &kdf->kdf_key, &out_civkey->key);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_derive_default_civkey(const struct silofs_mdigest *md,
                                 const struct silofs_password *pw,
                                 struct silofs_civkey *out_civkey)
{
	return derive_civkey(md, pw, &s_kdf_descs_default, out_civkey);
}
