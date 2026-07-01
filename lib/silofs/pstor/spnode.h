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
#ifndef SILOFS_SPNODE_H_
#define SILOFS_SPNODE_H_

#include <silofs/infra.h>
#include <silofs/nodes.h>

struct silofs_vspace_ref {
	size_t             refcnt;
	enum silofs_spacef flags;
};

struct silofs_spnode_info *silofs_spi_from_lni(struct silofs_lnode_info *lni);

void silofs_spi_incref(struct silofs_spnode_info *spi);

void silofs_spi_decref(struct silofs_spnode_info *spi);

void silofs_spi_setup_spawned(struct silofs_spnode_info *spi,
                              const struct silofs_laddr *ref_laddr);

void silofs_spi_setup_staged(struct silofs_spnode_info *spi);

int silofs_spi_find_free(const struct silofs_spnode_info *spi,
                         struct silofs_laddr             *out_laddr);

void silofs_spi_inc_allocated(struct silofs_spnode_info *spi,
                              const struct silofs_laddr *laddr);

void silofs_spi_dec_allocated(struct silofs_spnode_info *spi,
                              const struct silofs_laddr *laddr);

void silofs_spi_mark_unwritten(struct silofs_spnode_info *spi,
                               const struct silofs_laddr *laddr);

void silofs_spi_clear_unwritten(struct silofs_spnode_info *spi,
                                const struct silofs_laddr *laddr);

void silofs_spi_vspace_ref(const struct silofs_spnode_info *spi,
                           const struct silofs_laddr       *laddr,
                           struct silofs_vspace_ref        *out_vspref);

void silofs_spi_clone_from(struct silofs_spnode_info       *spi,
                           const struct silofs_spnode_info *spi_other);

int silofs_verify_space_node(const struct silofs_space_node *spn);

#endif /* SILOFS_SPNODE_H_ */
