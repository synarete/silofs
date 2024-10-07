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
#ifndef SILOFS_PS_PRIVATE_H_
#define SILOFS_PS_PRIVATE_H_

#ifndef SILOFS_HAVE_PRIVATE
#error "internal library header -- do not include!"
#endif

#include <silofs/infra.h>
#include <silofs/defs.h>


#define pni_ptype(pni)                  silofs_pni_ptype(pni)
#define pni_undirtify(pni)              silofs_pni_undirtify(pni)

#define bti_dirtify(bti)                silofs_bti_dirtify(bti)
#define bti_undirtify(bti)              silofs_bti_undirtify(bti)

#define bli_dirtify(bli)                silofs_bli_dirtify(bli)
#define bli_undirtify(bli)              silofs_bli_undirtify(bli)

#endif /* SILOFS_PS_PRIVATE_H_ */
