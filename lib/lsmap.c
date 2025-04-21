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
#include "configs.h"
#include <stdlib.h>
#include <limits.h>
#include <silofs/errors.h>
#include "infra.h"
#include "addr/htox.h"
#include "lsmap.h"

static size_t lbr_refcnt(const struct silofs_lbk_ref *lbr)
{
	return silofs_le64_to_cpu(lbr->lbr_refcnt);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lbk_ref *
lsmap_lbr_at2(const struct silofs_lsmap *lsm, size_t slot)
{
	return &lsm->lsm_lbrs[slot];
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_lbk_ref(const struct silofs_lbk_ref *lbr)
{
	size_t val;

	val = lbr_refcnt(lbr);
	if (val >= INT_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_lsmap(const struct silofs_lsmap *lsm)
{
	const struct silofs_lbk_ref *lbr;
	int err = 0;

	for (size_t i = 0; i < ARRAY_SIZE(lsm->lsm_lbrs) && !err; ++i) {
		lbr = lsmap_lbr_at2(lsm, i);
		err = verify_lbk_ref(lbr);
	}
	return err;
}
