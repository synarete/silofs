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
#ifndef SILOFS_CARVE_H_
#define SILOFS_CARVE_H_

int silofs_carve_base_ubspace(const struct silofs_exec_ctx *ectx,
                              struct silofs_pnptr          *out_pnptr);

int silofs_carve_base_btspace(const struct silofs_exec_ctx *ectx,
                              enum silofs_ltype             ltype,
                              struct silofs_pnptr          *out_pnptr);

int silofs_carve_base_lspace(const struct silofs_exec_ctx *ectx,
                             enum silofs_ltype             ltype,
                             struct silofs_paddr          *out_paddr);

int silofs_carve_btspace_pnptr(const struct silofs_exec_ctx *ectx,
                               enum silofs_ltype             ltype,
                               struct silofs_pnptr          *out_pnptr);

int silofs_carve_lspace_pnptr(const struct silofs_exec_ctx *ectx,
                              enum silofs_ltype             ltype,
                              struct silofs_pnptr          *out_pnptr);

#endif /* SILOFS_CARVE_H_ */
