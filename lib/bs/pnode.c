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
#include "configs.h"
#include "infra.h"
#include "addr.h"
#include "pnode.h"

void silofs_pni_init(struct silofs_pnode_info *pni,
                     const struct silofs_baddr *baddr)
{
	silofs_baddr_assign(&pni->pn_baddr, baddr);
	silofs_hmqe_init(&pni->pn_hmqe, silofs_mtype_size(baddr->mtype));
	silofs_hkey_by_baddr(&pni->pn_hmqe.hme_key, &pni->pn_baddr);
}

void silofs_pni_fini(struct silofs_pnode_info *pni)
{
	silofs_baddr_fini(&pni->pn_baddr);
	silofs_hmqe_fini(&pni->pn_hmqe);
}

enum silofs_mtype silofs_pni_mtype(const struct silofs_pnode_info *pni)
{
	return pni->pn_baddr.mtype;
}

static struct silofs_dq_elem *pni_dqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
pni_dqe2(const struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

void silofs_pni_set_dq(struct silofs_pnode_info *pni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(pni_dqe(pni), dq);
}

static bool pni_isdirty(const struct silofs_pnode_info *pni)
{
	return silofs_dqe_is_dirty(pni_dqe2(pni));
}

void silofs_pni_dirtify(struct silofs_pnode_info *pni)
{
	if (!pni_isdirty(pni)) {
		silofs_dqe_enqueue(pni_dqe(pni));
	}
}

void silofs_pni_undirtify(struct silofs_pnode_info *pni)
{
	if (pni_isdirty(pni)) {
		silofs_dqe_dequeue(pni_dqe(pni));
	}
}

void silofs_pni_incref(struct silofs_pnode_info *pni)
{
	silofs_hmqe_incref(&pni->pn_hmqe);
}

void silofs_pni_decref(struct silofs_pnode_info *pni)
{
	silofs_hmqe_decref(&pni->pn_hmqe);
}
