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
#ifndef SILOFS_FSREF_H_
#define SILOFS_FSREF_H_

#include <silofs/types.h>

void silofs_fsref_export(struct silofs_fsref       *fsref,
			 const struct silofs_mbref *mbref);

int silofs_fsref_import(const struct silofs_fsref *fsref,
			struct silofs_mbref       *out_mbref);


void silofs_fsrefs_export(struct silofs_fsrefs *fsrefs,
			  const struct silofs_mbrefs       *mbrefs);

#endif /* SILOFS_FSREF_H_ */
