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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include "infra.h"
#include "mbref.h"
#include "fsref.h"

static void fsref_reset(struct silofs_fsref *fsref)
{
	silofs_memzero(fsref, sizeof(*fsref));
}

static void fsref_setup_meta(struct silofs_fsref *fsref)
{
	struct silofs_meta *meta    = &fsref->meta;
	const char         *version = silofs_version.string;

	strncpy(meta->version, version, sizeof(meta->version) - 1);
	meta->btime   = (uint64_t)silofs_time_real_now();
	meta->fmtvers = SILOFS_FMT_VERSION;
}

static void fsref_encode_mbref(struct silofs_fsref       *fsref,
                               const struct silofs_mbref *mbref)
{
	silofs_mbref_to_str(mbref, fsref->mbref, sizeof(fsref->mbref) - 1);
}

void silofs_fsref_encode(struct silofs_fsref       *fsref,
                         const struct silofs_mbref *mbref)
{
	fsref_reset(fsref);
	fsref_setup_meta(fsref);
	fsref_encode_mbref(fsref, mbref);
}

static int fsref_check_meta(const struct silofs_fsref *fsref)
{
	const struct silofs_meta *meta = &fsref->meta;

	if (meta->fmtvers != SILOFS_FMT_VERSION) {
		return -SILOFS_EINVAL;
	}
	if (!meta->btime) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int fsref_decode_mbref(const struct silofs_fsref *fsref,
                              struct silofs_mbref       *out_mbref)
{
	size_t len;
	int    err = -SILOFS_EINVAL;

	len = silofs_str_nlength(fsref->mbref, sizeof(fsref->mbref));
	if (len && (len < sizeof(fsref->mbref))) {
		err = silofs_mbref_from_str(out_mbref, fsref->mbref, len);
	}
	return err;
}

int silofs_fsref_decode(const struct silofs_fsref *fsref,
                        struct silofs_mbref       *out_mbref)
{
	int err;

	err = fsref_check_meta(fsref);
	if (err) {
		return err;
	}
	err = fsref_decode_mbref(fsref, out_mbref);
	if (err) {
		return err;
	}
	return 0;
}
