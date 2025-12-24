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
#ifndef SILOFS_HMAC_H_
#define SILOFS_HMAC_H_

#include <silofs/ondisk.h>

/* wrapper over libgcrypt mac handle */
struct silofs_hmac_hd {
	gcry_mac_hd_t hm_hd;
	int           hm_algo;
};

int silofs_hmac_init(struct silofs_hmac_hd *hm_hd);

void silofs_hmac_fini(struct silofs_hmac_hd *hm_hd);

int silofs_hmac_calc(struct silofs_hmac_hd    *hm_hd,
                     const struct silofs_ckey *key, const void *dat,
                     size_t dsz, struct silofs_mac *out_mac);

#endif /* SILOFS_HMAC_H_ */
