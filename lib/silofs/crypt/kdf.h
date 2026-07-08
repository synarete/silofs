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
#ifndef SILOFS_KDF_H_
#define SILOFS_KDF_H_

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

#endif /* SILOFS_KDF_H_ */
