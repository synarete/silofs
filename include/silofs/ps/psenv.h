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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef SILOFS_PSENV_H_
#define SILOFS_PSENV_H_

#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>
#include <silofs/ps/repo.h>
#include <silofs/ps/bcache.h>


struct silofs_pstate {
	struct silofs_psid beg;
	struct silofs_psid cur;
	loff_t cur_pos;
};

struct silofs_psenv {
	struct silofs_repo     *repo;
	struct silofs_alloc    *alloc;
	struct silofs_bcache    bcache;
	struct silofs_pstate    pstate;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_psenv_init(struct silofs_psenv *psenv,
                      struct silofs_repo *repo);

void silofs_psenv_fini(struct silofs_psenv *psenv);


int silofs_format_btree(struct silofs_psenv *psenv);


#endif /* SILOFS_PSENV_H_ */
