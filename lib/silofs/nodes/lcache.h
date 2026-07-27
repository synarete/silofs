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
#ifndef SILOFS_LCACHE_H_
#define SILOFS_LCACHE_H_

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

/* in-memory caching */
struct silofs_lcache {
	struct silofs_ncache nc;
};

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc  *alloc);

void silofs_lcache_fini(struct silofs_lcache *lcache);

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags);

void silofs_lcache_drop(struct silofs_lcache *lcache);

struct silofs_lnode_info *
silofs_lcache_lookup_lnode(struct silofs_lcache      *lcache,
                           const struct silofs_laddr *laddr);

struct silofs_lnode_info *
silofs_lcache_create_lnode(struct silofs_lcache      *lcache,
                           const struct silofs_laddr *laddr);

void silofs_lcache_forget_lnode(struct silofs_lcache     *lcache,
                                struct silofs_lnode_info *lni);

#endif /* SILOFS_LCACHE_H_ */
