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
#ifndef SILOFS_VOLID_H_
#define SILOFS_VOLID_H_

#include <silofs/defs.h>

struct silofs_strview;
struct silofs_strbuf;

void silofs_volid_generate(struct silofs_volid *volid);

void silofs_volid_reset(struct silofs_volid *volid);

void silofs_volid_assign(struct silofs_volid       *volid,
                         const struct silofs_volid *other);

long silofs_volid_compare(const struct silofs_volid *volid1,
                          const struct silofs_volid *volid2);

bool silofs_volid_isequal(const struct silofs_volid *volid1,
                          const struct silofs_volid *volid2);

void silofs_volid_to_str(const struct silofs_volid *volid,
                         struct silofs_strbuf      *sbuf);

int silofs_volid_from_str(struct silofs_volid         *volid,
                          const struct silofs_strview *sv);

void silofs_volid_by_uuid(struct silofs_volid      *volid,
                          const struct silofs_uuid *uuid);

#endif /* SILOFS_VOLID_H_ */
