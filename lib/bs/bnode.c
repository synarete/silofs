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
#include "bnode.h"

static size_t baddr_size(const struct silofs_baddr *baddr)
{
	return silofs_mtype_size(baddr->mtype);
}

void silofs_bni_init(struct silofs_bnode_info *bni,
                     const struct silofs_baddr *baddr)
{
	silofs_baddr_assign(&bni->bn_baddr, baddr);
	silofs_hmqe_init(&bni->bn_hmqe, baddr_size(baddr));
	silofs_hkey_by_baddr(&bni->bn_hmqe.hme_key, &bni->bn_baddr);
}

void silofs_bni_fini(struct silofs_bnode_info *bni)
{
	silofs_baddr_fini(&bni->bn_baddr);
	silofs_hmqe_fini(&bni->bn_hmqe);
}

enum silofs_mtype silofs_bni_mtype(const struct silofs_bnode_info *bni)
{
	return bni->bn_baddr.mtype;
}

static struct silofs_dq_elem *bni_dqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
bni_dqe2(const struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

void silofs_bni_set_dq(struct silofs_bnode_info *bni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(bni_dqe(bni), dq);
}

static bool bni_isdirty(const struct silofs_bnode_info *bni)
{
	return silofs_dqe_is_dirty(bni_dqe2(bni));
}

void silofs_bni_dirtify(struct silofs_bnode_info *bni)
{
	if (!bni_isdirty(bni)) {
		silofs_dqe_enqueue(bni_dqe(bni));
	}
}

void silofs_bni_undirtify(struct silofs_bnode_info *bni)
{
	if (bni_isdirty(bni)) {
		silofs_dqe_dequeue(bni_dqe(bni));
	}
}

void silofs_bni_incref(struct silofs_bnode_info *bni)
{
	silofs_hmqe_incref(&bni->bn_hmqe);
}

void silofs_bni_decref(struct silofs_bnode_info *bni)
{
	silofs_hmqe_decref(&bni->bn_hmqe);
}
