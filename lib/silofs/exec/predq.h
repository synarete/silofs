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
#ifndef SILOFS_PREDQ_H_
#define SILOFS_PREDQ_H_

#include <silofs/nodes.h>

struct silofs_iis_predq {
	struct silofs_listq lsq;
};

void silofs_iis_preqd_init(struct silofs_iis_predq *iis_predq);

void silofs_iis_preqd_fini(struct silofs_iis_predq *iis_predq);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_add_to_predq(struct silofs_iis_predq  *iis_predq,
                         struct silofs_inode_info *ii,
                         struct silofs_lnode_info *lni);

void silofs_rm_from_predq(struct silofs_iis_predq  *iis_predq,
                          struct silofs_inode_info *ii,
                          struct silofs_lnode_info *lni);

void silofs_apply_predq_of(struct silofs_iis_predq  *iis_predq,
                           struct silofs_inode_info *ii);

void silofs_clear_predq_of(struct silofs_iis_predq  *iis_predq,
                           struct silofs_inode_info *ii);

void silofs_flush_iis_predq(struct silofs_iis_predq *iis_predq);

#endif /* SILOFS_PREDQ_H_ */
