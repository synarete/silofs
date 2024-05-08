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
#ifndef SILOFS_PACKID_H_
#define SILOFS_PACKID_H_

/* packed-object identifier */
struct silofs_packid {
	struct silofs_hash256 hash;
};


void silofs_packid_setup(struct silofs_packid *packid,
                         const struct silofs_hash256 *hash);

void silofs_packid_assign(struct silofs_packid *packid,
                          const struct silofs_packid *other);

bool silofs_packid_isnone(const struct silofs_packid *packid);

void silofs_packid_to_name(const struct silofs_packid *packid,
                           struct silofs_strbuf *out_name);

void silofs_packid_to_base64(const struct silofs_packid *packid,
                             struct silofs_strbuf *out_sbuf);


void silofs_packid64b_htox(struct silofs_packid64b *packid64b,
                           const struct silofs_packid *packid);

void silofs_packid64b_xtoh(const struct silofs_packid64b *packid64b,
                           struct silofs_packid *packid);

#endif /* SILOFS_PACKID_H_ */
