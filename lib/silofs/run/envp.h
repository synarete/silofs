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
#ifndef SILOFS_ENVP_H_
#define SILOFS_ENVP_H_

#ifndef SILOFS_USE_ENV_PRIVATE
#error "env private header -- do not include"
#endif

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVIF_PRANDGEN = SILOFS_BIT(0),
	SILOFS_ENVIF_QALLOC   = SILOFS_BIT(1),
	SILOFS_ENVIF_STDALLOC = SILOFS_BIT(2),
	SILOFS_ENVIF_REPO     = SILOFS_BIT(3),
	SILOFS_ENVIF_PCACHE   = SILOFS_BIT(4),
	SILOFS_ENVIF_LCACHE   = SILOFS_BIT(5),
	SILOFS_ENVIF_FREESQS  = SILOFS_BIT(6),
	SILOFS_ENVIF_IDSMAP   = SILOFS_BIT(9),
	SILOFS_ENVIF_FUSEQ    = SILOFS_BIT(11),
	SILOFS_ENVIF_ENV      = SILOFS_BIT(12),
};

/* memory allocator of choice */
union silofs_alloc_u {
	struct silofs_qalloc   qalloc;
	struct silofs_stdalloc stdalloc;
};

/* actual environment instance object (internal) */
struct silofs_env_inst {
	struct silofs_prandgen prandgen;
	union silofs_alloc_u   alloc_u;
	struct silofs_repo     repo;
	struct silofs_pcache   pcache;
	struct silofs_lcache   lcache;
	struct silofs_lspools  lspools;
	struct silofs_pspools  pspool;
	struct silofs_idsmap   idsmap;
	struct silofs_env      env;
	struct silofs_alloc   *alloc;
	struct silofs_lblock  *nilbk;
	struct silofs_fuseq   *fuseq;
	long                   initf;
};

#endif /* SILOFS_ENVP_H_ */
