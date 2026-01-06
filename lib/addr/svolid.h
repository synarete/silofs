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
#ifndef SILOFS_SVOLID_H_
#define SILOFS_SVOLID_H_

#include <silofs/ondisk.h>

const struct silofs_svolid *silofs_svolid_none(void);

void silofs_svolid_reset(struct silofs_svolid *svolid);

void silofs_svolid_generate(struct silofs_svolid *svolid);

void silofs_svolid_copyto(const struct silofs_svolid *svolid,
                          struct silofs_svolid       *other);

bool silofs_svolid_isequal(const struct silofs_svolid *svolid,
                           const struct silofs_svolid *other);

#endif /* SILOFS_SVOLID_H_ */
