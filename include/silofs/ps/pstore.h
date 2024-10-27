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
#ifndef SILOFS_PSTORE_H_
#define SILOFS_PSTORE_H_

#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>
#include <silofs/ps/repo.h>
#include <silofs/ps/bcache.h>


struct silofs_pstsub {
	struct silofs_psid beg;
	struct silofs_psid cur;
	loff_t cur_pos;
};

struct silofs_pstate {
	struct silofs_pstsub meta;
	struct silofs_pstsub data;
};

struct silofs_pstore {
	struct silofs_repo     *repo;
	struct silofs_alloc    *alloc;
	struct silofs_bcache    bcache;
	struct silofs_pstate    pstate;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pstore_init(struct silofs_pstore *pstore,
                       struct silofs_repo *repo);

void silofs_pstore_fini(struct silofs_pstore *pstore);

int silofs_pstore_dropall(struct silofs_pstore *pstore);

int silofs_pstore_format(struct silofs_pstore *pstore);

int silofs_pstore_flush_dirty(struct silofs_pstore *pstore);


#endif /* SILOFS_PSTORE_H_ */
