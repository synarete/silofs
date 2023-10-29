/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

#include <silofs/fs/types.h>

int silofs_uber_init(struct silofs_uber *uber,
                     const struct silofs_uber_base *base);

void silofs_uber_fini(struct silofs_uber *uber);

time_t silofs_uber_uptime(const struct silofs_uber *uber);

void silofs_uber_shut(struct silofs_uber *uber);

void silofs_uber_bind_child(struct silofs_uber *uber,
                            const struct silofs_ulink *ulink);

int silofs_uber_format_super(struct silofs_uber *uber, size_t capacity);

int silofs_uber_reload_super(struct silofs_uber *uber);

int silofs_uber_reload_sb_lext(struct silofs_uber *uber);

int silofs_uber_forkfs(struct silofs_uber *uber,
                       struct silofs_bootrecs *out_brecs);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_super_at(struct silofs_uber *uber,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi);

int silofs_stage_super_at(struct silofs_uber *uber,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi);


int silofs_spawn_spnode_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni);

int silofs_stage_spnode_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni);


int silofs_spawn_spleaf_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_ubk_at(struct silofs_uber *uber,
                        const struct silofs_laddr *laddr,
                        struct silofs_ubk_info **out_ubki);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_lext_at(struct silofs_uber *uber,
                         const struct silofs_lextid *lextid);

int silofs_stage_lext_at(struct silofs_uber *uber,
                         const struct silofs_lextid *lextid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_relax_caches(const struct silofs_task *task, int flags);

#endif /* SILOFS_UBER_H_ */
