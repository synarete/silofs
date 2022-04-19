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
#ifndef SILOFS_UMETA_H_
#define SILOFS_UMETA_H_


int silofs_spawn_super_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_stage_super_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_shadow_super_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi);


int silofs_spawn_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_stats_info **out_sti);

int silofs_stage_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_stats_info **out_sti);

int silofs_shadow_stats_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_stats_info **out_sti);


int silofs_spawn_spnode_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_stage_spnode_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_shadow_spnode_at(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni);


int silofs_spawn_spleaf_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_shadow_spleaf_at(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spleaf_info **out_sli);

#endif /* SILOFS_UMETA_H_ */
