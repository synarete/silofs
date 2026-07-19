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
#ifndef SILOFS_MBROPS_H_
#define SILOFS_MBROPS_H_

#include <silofs/infra.h>
#include <silofs/addr.h>

int silofs_sense_mbr(const struct silofs_core_refs *corefs,
                     const struct silofs_mbref     *mbref);

int silofs_commit_mbr(const struct silofs_core_refs *corefs,
                      struct silofs_mbref           *out_mbref);

int silofs_reload_mbr(const struct silofs_core_refs *corefs,
                      const struct silofs_mbref     *mbref);

int silofs_unref_mbr(const struct silofs_core_refs *corefs,
                     const struct silofs_mbref     *mbref);

#endif /* SILOFS_MBROPS_H_ */
