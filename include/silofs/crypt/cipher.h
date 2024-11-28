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
#ifndef SILOFS_CIPHER_H_
#define SILOFS_CIPHER_H_

#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <gcrypt.h>

#define SILOFS_CIPHER_ALGO_DEFAULT SILOFS_CIPHER_AES256
#define SILOFS_CIPHER_MODE_DEFAULT SILOFS_CIPHER_MODE_GCM

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

struct silofs_cipher {
	gcry_cipher_hd_t cipher_hd;
	int              cipher_algo;
	int              cipher_mode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_cipher_args(int algo, int mode);

int silofs_cipher_init(struct silofs_cipher *ci);

int silofs_cipher_reinit(struct silofs_cipher *ci, int algo, int mode);

void silofs_cipher_fini(struct silofs_cipher *ci);

int silofs_encrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey, const void *in_dat,
                       void *out_dat, size_t dat_len);

int silofs_decrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey, const void *in_dat,
                       void *out_dat, size_t dat_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_derive_boot_ivkey(const struct silofs_mdigest  *md,
                             const struct silofs_password *pw,
                             struct silofs_ivkey          *out_ivkey);

#endif /* SILOFS_CIPHER_H_ */
