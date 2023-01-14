/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_UBER_H_
#define SILOFS_UBER_H_

#include <silofs/types.h>

struct silofs_uber_args {
	struct silofs_alloc    *alloc;
	struct silofs_repos    *repos;
	struct silofs_flushers *fls;
	struct silofs_idsmap   *idsm;
	const struct silofs_ivkey *ivkey;
};


int silofs_uber_init(struct silofs_uber *uber,
                     const struct silofs_uber_args *args);

void silofs_uber_fini(struct silofs_uber *uber);

time_t silofs_uber_uptime(const struct silofs_uber *uber);

void silofs_uber_shut(struct silofs_uber *uber);

void silofs_uber_set_sbaddr(struct silofs_uber *uber,
                            const struct silofs_uaddr *sb_addr);

int silofs_uber_format_supers(struct silofs_uber *uber, size_t capacity);

int silofs_uber_reload_supers(struct silofs_uber *uber);

int silofs_uber_reload_sblob(struct silofs_uber *uber);

int silofs_uber_forkfs(struct silofs_uber *uber,
                       struct silofs_bootsecs *out_bsecs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_super_at(struct silofs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_stage_super_at(struct silofs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_shadow_super_at(struct silofs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi);


int silofs_spawn_spnode_at(struct silofs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_stage_spnode_at(struct silofs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_shadow_spnode_at(struct silofs_uber *uber, bool warm,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni);


int silofs_spawn_spleaf_at(struct silofs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf_at(struct silofs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_shadow_spleaf_at(struct silofs_uber *uber, bool warm,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spleaf_info **out_sli);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_ubk_at(struct silofs_uber *uber, bool warm,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_ubk_info **out_ubki);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_blob_at(struct silofs_uber *uber, bool warm,
                         const struct silofs_blobid *blobid,
                         struct silofs_blobref_info **out_bri);

int silofs_stage_blob_at(struct silofs_uber *uber, bool warm,
                         const struct silofs_blobid *blobid,
                         struct silofs_blobref_info **out_bri);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_relax_caches(struct silofs_task *task, int flags);

#endif /* SILOFS_UBER_H_ */
