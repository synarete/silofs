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
#include <silofs/configs.h>

#include <silofs/exec.h>

void silofs_relax_caches(const struct silofs_exec_refs *xrefs, int flags)
{
	silofs_pcache_relax(xrefs->pcache, flags);
	silofs_lcache_relax(xrefs->lcache, flags);
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_dstor_relax(xrefs->dstor);
	}
}

void silofs_drop_caches(const struct silofs_exec_refs *xrefs)
{
	silofs_pspools_drop(xrefs->pspools);
	silofs_lspools_drop(xrefs->lspools);
	silofs_pcache_drop(xrefs->pcache);
	silofs_lcache_drop(xrefs->lcache);
	silofs_dstor_drop(xrefs->dstor);
}
