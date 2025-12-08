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
#ifndef SILOFS_CMETA_H_
#define SILOFS_CMETA_H_

#include "crypt.h"
#include "paddr.h"

/* node's cryptographic meta params */
struct silofs_cmeta {
	struct silofs_civkey civkey;
	struct silofs_ciargs ciargs;
};

/* persistent nodes meta params */
struct silofs_pmeta {
	struct silofs_cmeta cmeta;
	struct silofs_paddr paddr;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_cmeta *silofs_cmeta_none(void);

void silofs_cmeta_setup(struct silofs_cmeta        *cmeta,
                        const struct silofs_civkey *civkey);

void silofs_cmeta_reset(struct silofs_cmeta *cmeta);

void silofs_cmeta_assign(struct silofs_cmeta       *cmeta,
                         const struct silofs_cmeta *other);

void silofs_cmeta96b_htox(struct silofs_cmeta96b    *cmeta96,
                          const struct silofs_cmeta *cmeta);

void silofs_cmeta96b_xtoh(const struct silofs_cmeta96b *cmeta96,
                          struct silofs_cmeta          *cmeta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pmeta *silofs_pmeta_none(void);

void silofs_pmeta_setup(struct silofs_pmeta        *pmeta,
                        const struct silofs_paddr  *paddr,
                        const struct silofs_civkey *civkey);

void silofs_pmeta_setup2(struct silofs_pmeta       *pmeta,
                         const struct silofs_paddr *paddr,
                         const struct silofs_cmeta *cmeta);

void silofs_pmeta_reset(struct silofs_pmeta *pmeta);

void silofs_pmeta_assign(struct silofs_pmeta       *pmeta,
                         const struct silofs_pmeta *other);

bool silofs_pmeta_isnull(const struct silofs_pmeta *pmeta);

void silofs_pmeta192b_htox(struct silofs_pmeta192b   *pmeta192,
                           const struct silofs_pmeta *pmeta);

void silofs_pmeta192b_xtoh(const struct silofs_pmeta192b *pmeta192,
                           struct silofs_pmeta           *pmeta);

#endif /* SILOFS_CMETA_H_ */
