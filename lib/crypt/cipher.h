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
#ifndef SILOFS_CIPHER_H_
#define SILOFS_CIPHER_H_

#include <gcrypt.h>
#include <silofs/ondisk.h>
#include "ivkey.h"
#include "mdigest.h"
#include "passwd.h"

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

/* cipher's operation arguments */
struct silofs_ciargs {
	enum silofs_cipher_algo algo;
	enum silofs_cipher_mode mode;
};

/* wrapper over libgcrypt cipher */
struct silofs_cipher {
	gcry_cipher_hd_t     ci_hd;
	struct silofs_ciargs ci_args;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_ciargs *silofs_ciargs_default(void);

void silofs_ciargs_setup(struct silofs_ciargs *ciargs);

void silofs_ciargs_assign(struct silofs_ciargs       *ciargs,
                          const struct silofs_ciargs *other);

int silofs_ciargs_check(const struct silofs_ciargs *ciargs);

int silofs_cipher_init(struct silofs_cipher *cipher);

int silofs_cipher_reinit(struct silofs_cipher       *cipher,
                         const struct silofs_ciargs *ciargs);

void silofs_cipher_fini(struct silofs_cipher *cipher);

int silofs_cipher_check(const struct silofs_cipher *cipher,
                        const struct silofs_ciargs *ciargs);

int silofs_encrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey, const void *in_dat,
                       void *out_dat, size_t dat_len);

int silofs_decrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey, const void *in_dat,
                       void *out_dat, size_t dat_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_derive_default_ivkey(const struct silofs_mdigest  *md,
                                const struct silofs_password *pw,
                                struct silofs_ivkey          *out_ivkey);

#endif /* SILOFS_CIPHER_H_ */
