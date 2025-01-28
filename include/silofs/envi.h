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
#ifndef SILOFS_ENVI_H_
#define SILOFS_ENVI_H_

#include <silofs/macros.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/env.h>

/* env initialization-state flags */
enum silofs_env_initf {
	SILOFS_ENVIF_QALLOC   = SILOFS_BIT(0),
	SILOFS_ENVIF_STDALLOC = SILOFS_BIT(1),
	SILOFS_ENVIF_REPO     = SILOFS_BIT(2),
	SILOFS_ENVIF_PCACHE   = SILOFS_BIT(3),
	SILOFS_ENVIF_LCACHE   = SILOFS_BIT(4),
	SILOFS_ENVIF_SUBMITQ  = SILOFS_BIT(5),
	SILOFS_ENVIF_IDSMAP   = SILOFS_BIT(6),
	SILOFS_ENVIF_BSTORE   = SILOFS_BIT(7),
	SILOFS_ENVIF_FLUSHER  = SILOFS_BIT(8),
	SILOFS_ENVIF_FUSEQ    = SILOFS_BIT(9),
	SILOFS_ENVIF_ENV      = SILOFS_BIT(10),
};

/* memory allocator of choice */
union silofs_alloc_u {
	struct silofs_qalloc   qalloc;
	struct silofs_stdalloc stdalloc;
};

/* actual environment instance object (internal) */
struct silofs_env_inst {
	struct silofs_password passwd;
	struct silofs_args     args;
	union silofs_alloc_u   alloc_u;
	struct silofs_repo     repo;
	struct silofs_pcache   pcache;
	struct silofs_lcache   lcache;
	struct silofs_submitq  submitq;
	struct silofs_idsmap   idsmap;
	struct silofs_bstore   bstore;
	struct silofs_flusher  flusher;
	struct silofs_env      env;
	struct silofs_alloc   *alloc;
	struct silofs_fuseq   *fuseq;
	long                   initf;
};

#endif /* SILOFS_ENVI_H_ */
