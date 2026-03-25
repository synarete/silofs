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
#ifndef SILOFS_SPDESC_H_
#define SILOFS_SPDESC_H_

#include <silofs/addr/paddr.h>

/* space descriptor as p-addresses range */
struct silofs_spdesc {
	struct silofs_paddr beg;
	struct silofs_paddr end;
};

const struct silofs_spdesc *silofs_spdesc_none(void);

void silofs_spdesc_setup(struct silofs_spdesc      *spdesc,
                         const struct silofs_paddr *beg,
                         const struct silofs_paddr *end);

void silofs_spdesc_setup1(struct silofs_spdesc      *spdesc,
                          const struct silofs_paddr *beg);

void silofs_spdesc_htox(struct silofs_spdesc128b   *spdesc128,
                        const struct silofs_spdesc *spdesc);

void silofs_spdesc_xtoh(const struct silofs_spdesc128b *spdesc128,
                        struct silofs_spdesc           *spdesc);

#endif /* SILOFS_SPDESC_H_ */
