/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>


int silofs_psenv_init(struct silofs_psenv *psenv,
                      struct silofs_repo *repo)
{
	psenv->repo = repo;
	psenv->alloc = repo->re.alloc;
	return silofs_bcache_init(&psenv->bcache, psenv->alloc);
}

void silofs_psenv_fini(struct silofs_psenv *psenv)
{
	silofs_bcache_drop(&psenv->bcache);
	silofs_bcache_fini(&psenv->bcache);
	psenv->alloc = NULL;
	psenv->repo = NULL;
}
