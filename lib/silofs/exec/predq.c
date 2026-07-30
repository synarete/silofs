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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/exec.h>

static bool lni_test_predq_flag(const struct silofs_lnode_info *lni)
{
	return silofs_ni_testf(&lni->ln_ni, SILOFS_NIF_PREDQ);
}

static void lni_set_predq_flag(struct silofs_lnode_info *lni)
{
	silofs_ni_setf(&lni->ln_ni, SILOFS_NIF_PREDQ);
}

static void lni_clear_predq_flag(struct silofs_lnode_info *lni)
{
	silofs_ni_clearf(&lni->ln_ni, SILOFS_NIF_PREDQ);
}

static struct silofs_lnode_info *lni_from_predq_lh(struct silofs_list_head *lh)
{
	struct silofs_lnode_info *lni = nullptr;

	if (lh != nullptr) {
		lni = mut_container_of(lh, struct silofs_lnode_info,
		                       ln_predq_lh);
	}
	return lni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ii_test_predq_flag(const struct silofs_inode_info *ii)
{
	return lni_test_predq_flag(&ii->i_lni);
}

static void ii_set_predq_flag(struct silofs_inode_info *ii)
{
	lni_set_predq_flag(&ii->i_lni);
}

static void ii_clear_predq_flag(struct silofs_inode_info *ii)
{
	lni_clear_predq_flag(&ii->i_lni);
}

static void
ii_add_to_predq(struct silofs_inode_info *ii, struct silofs_lnode_info *lni)
{
	if (!lni_test_predq_flag(lni)) {
		silofs_listq_push_back(&ii->i_predq, &lni->ln_predq_lh);
		lni_set_predq_flag(lni);
	}
}

static void
ii_rm_from_predq(struct silofs_inode_info *ii, struct silofs_lnode_info *lni)
{
	if (lni_test_predq_flag(lni)) {
		silofs_listq_remove(&ii->i_predq, &lni->ln_predq_lh);
		lni_clear_predq_flag(lni);
	}
}

static bool ii_has_predq(const struct silofs_inode_info *ii)
{
	return (ii->i_predq.sz > 0);
}

static struct silofs_inode_info *ii_from_predq_lh(struct silofs_list_head *lh)
{
	struct silofs_lnode_info *lni = lni_from_predq_lh(lh);

	return silofs_ii_from_lni(lni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_iis_preqd_init(struct silofs_iis_predq *iis_predq)
{
	silofs_listq_init(&iis_predq->lsq);
}

void silofs_iis_preqd_fini(struct silofs_iis_predq *iis_predq)
{
	silofs_assert_eq(iis_predq->lsq.sz, 0);
	silofs_listq_fini(&iis_predq->lsq);
}

static struct silofs_inode_info *
iis_predq_front(const struct silofs_iis_predq *iis_predq)
{
	struct silofs_list_head *lh;

	lh = silofs_listq_front(&iis_predq->lsq);
	return ii_from_predq_lh(lh);
}

static void add_to_iis_predq(struct silofs_iis_predq *iis_predq,
                             struct silofs_inode_info *ii)
{
	if (!ii_test_predq_flag(ii)) {
		silofs_listq_push_back(&iis_predq->lsq,
		                       &ii->i_lni.ln_predq_lh);
		ii_set_predq_flag(ii);
	}
}

static void rm_from_iis_predq(struct silofs_iis_predq *iis_predq,
                              struct silofs_inode_info *ii)
{
	if (ii_test_predq_flag(ii)) {
		silofs_listq_remove(&iis_predq->lsq, &ii->i_lni.ln_predq_lh);
		ii_clear_predq_flag(ii);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_add_to_predq(struct silofs_iis_predq *iis_predq,
                         struct silofs_inode_info *ii,
                         struct silofs_lnode_info *lni)
{
	ii_add_to_predq(ii, lni);
	add_to_iis_predq(iis_predq, ii);
}

void silofs_rm_from_predq(struct silofs_iis_predq *iis_predq,
                          struct silofs_inode_info *ii,
                          struct silofs_lnode_info *lni)
{
	ii_rm_from_predq(ii, lni);
	if (!ii_has_predq(ii)) {
		rm_from_iis_predq(iis_predq, ii);
	}
}

static struct silofs_lnode_info *predq_front(struct silofs_inode_info *ii)
{
	struct silofs_list_head *lh;

	lh = silofs_listq_front(&ii->i_predq);
	return lni_from_predq_lh(lh);
}

void silofs_apply_predq_of(struct silofs_iis_predq *iis_predq,
                           struct silofs_inode_info *ii)
{
	struct silofs_lnode_info *lni;

	lni = predq_front(ii);
	while (lni != nullptr) {
		silofs_rm_from_predq(iis_predq, ii, lni);
		silofs_lni_setdirty(lni);
		lni = predq_front(ii);
	}
}

void silofs_clear_predq_of(struct silofs_iis_predq *iis_predq,
                           struct silofs_inode_info *ii)
{
	struct silofs_lnode_info *lni;

	lni = predq_front(ii);
	while (lni != nullptr) {
		silofs_rm_from_predq(iis_predq, ii, lni);
		lni = predq_front(ii);
	}
}

void silofs_flush_iis_predq(struct silofs_iis_predq *iis_predq)
{
	struct silofs_inode_info *ii;

	ii = iis_predq_front(iis_predq);
	while (ii != nullptr) {
		silofs_apply_predq_of(iis_predq, ii);
		ii = iis_predq_front(iis_predq);
	}
}
