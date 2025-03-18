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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

#include "str.h"

struct silofs_caddr;
struct silofs_xref;
struct silofs_task;

void silofs_xref_reset(struct silofs_xref *xref);

bool silofs_xref_isnull(const struct silofs_xref *xref);

void silofs_xref_from_caddr(struct silofs_xref        *xref,
                            const struct silofs_caddr *caddr);

int silofs_xref_to_caddr(const struct silofs_xref *xref,
                         struct silofs_caddr      *out_caddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_reload_vspace(struct silofs_task *task);

int silofs_reload_rootd(struct silofs_task *task);

#endif /* SILOFS_BOOT_H_ */
