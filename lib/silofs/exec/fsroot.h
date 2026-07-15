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
#ifndef SILOFS_FSROOT_H_
#define SILOFS_FSROOT_H_

#include <silofs/infra.h>
#include <silofs/addr.h>

/* main-boot-record meta-info */
struct silofs_mbr_meta {
	struct silofs_nmeta nmeta;
	struct silofs_ckey  hmac_key;
};

/* file-system's top-level operations counters/stats */
struct silofs_opstat {
	size_t op_iopen_max;
	size_t op_iopen;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* main boot-record, in-memory representation */
struct silofs_fsroot {
	struct silofs_rwlock     rwlock;
	struct silofs_mutex      mutex;
	struct silofs_baseref    baseref;
	struct silofs_mbr1k      mbr1k;
	struct silofs_mbref      mbref;
	struct silofs_mbr_meta   mbr_meta;
	struct silofs_opstat     opstat;
	struct silofs_uber_info *ubi;
	enum silofs_flags        ctl_flags;
	unsigned long            ms_flags;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fsroot_init(struct silofs_fsroot *fsroot);

void silofs_fsroot_fini(struct silofs_fsroot *fsroot);

void silofs_fsroot_reset_mbref(struct silofs_fsroot *fsroot);

void silofs_fsroot_lock(struct silofs_fsroot *fsroot);

void silofs_fsroot_unlock(struct silofs_fsroot *fsroot);

void silofs_fsroot_rwlock(struct silofs_fsroot *fsroot, bool ex);

void silofs_fsroot_rwunlock(struct silofs_fsroot *fsroot);

int silofs_fsroot_derive_meta(struct silofs_fsroot         *fsroot,
                              const struct silofs_password *passwd);

void silofs_fsroot_set_mbref(struct silofs_fsroot      *fsroot,
                             const struct silofs_mbref *mbref);

int silofs_fsroot_export_mbr1k(const struct silofs_fsroot *fsroot,
                               struct silofs_mbref        *out_mbref,
                               struct silofs_mbr1k        *out_mbr1k_enc);

int silofs_fsroot_import_mbr1k(struct silofs_fsroot      *fsroot,
                               const struct silofs_mbref *mbref,
                               const struct silofs_mbr1k *mbr1k_enc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_update_uber_ref(struct silofs_fsroot    *fsroot,
                            struct silofs_uber_info *ubi_new);

void silofs_update_main_ctlflags(struct silofs_fsroot *fsroot,
                                 enum silofs_flags     ctl_flags);

bool silofs_test_rdonly_fs(const struct silofs_fsroot *fsroot);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_resolve_root_uber(const struct silofs_fsroot *fsroot,
                             struct silofs_pnptr        *out_pnptr,
                             struct silofs_sw_version   *out_swv);

void silofs_update_root_uber(struct silofs_fsroot           *fsroot,
                             const struct silofs_pnptr      *pnptr,
                             const struct silofs_sw_version *swv);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_stat_mbr_at(struct silofs_dstor       *dstor,
                       const struct silofs_mbref *mbref);

#endif /* SILOFS_FSROOT_H_ */
