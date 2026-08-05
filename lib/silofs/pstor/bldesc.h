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
#ifndef SILOFS_BLDESC_H_
#define SILOFS_BLDESC_H_

#include <silofs/nodes.h>

void silofs_bdi_setdirty(struct silofs_bldesc_info *bdi);

void silofs_bdi_cleardirty(struct silofs_bldesc_info *bdi);

void silofs_bdi_ignite(struct silofs_bldesc_info *bdi);

void silofs_bdi_ignite2(struct silofs_bldesc_info  *bdi,
                        const struct silofs_blobid *blobid);

int silofs_bdi_find_free(const struct silofs_bldesc_info *bdi,
                         struct silofs_paddr             *out_paddr);

int silofs_bdi_test_free(const struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr       *paddr);

int silofs_bdi_mark_free(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr);

int silofs_bdi_mark_used(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr);

int silofs_validate_bldesc(const struct silofs_bldesc_info *bdi);

#endif /* SILOFS_BLDESC_H_ */
