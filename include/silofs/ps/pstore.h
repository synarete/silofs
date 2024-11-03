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


struct silofs_prange {
	struct silofs_psid psid;
	size_t nsegs;
	loff_t cur_pos;
};

struct silofs_pstate {
	struct silofs_prange    meta;
	struct silofs_prange    data;
};

struct silofs_pstore {
	struct silofs_repo     *repo;
	struct silofs_alloc    *alloc;
	struct silofs_bcache    bcache;
	struct silofs_pstate    pstate;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pstate_assign(struct silofs_pstate *pstate,
                          const struct silofs_pstate *other);

void silofs_pstate128b_htox(struct silofs_pstate128b *pstate128,
                            const struct silofs_pstate *pstate);

void silofs_pstate128b_xtoh(const struct silofs_pstate128b *pstate128,
                            struct silofs_pstate *pstate);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pstore_init(struct silofs_pstore *pstore,
                       struct silofs_repo *repo);

void silofs_pstore_fini(struct silofs_pstore *pstore);

int silofs_pstore_dropall(struct silofs_pstore *pstore);

int silofs_pstore_format(struct silofs_pstore *pstore);

int silofs_pstore_open(struct silofs_pstore *pstore,
                       const struct silofs_pstate *pstate);

int silofs_pstore_flush_dirty(struct silofs_pstore *pstore);


#endif /* SILOFS_PSTORE_H_ */
