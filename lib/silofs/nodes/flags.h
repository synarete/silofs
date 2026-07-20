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
#ifndef SILOFS_FLAGS_H_
#define SILOFS_FLAGS_H_

#include <silofs/macros.h>

/* control flags (internal) */
enum silofs_ctlf {
	SILOFS_CTLF_NOW     = SILOFS_BIT(0),
	SILOFS_CTLF_FSYNC   = SILOFS_BIT(1),
	SILOFS_CTLF_OPSTART = SILOFS_BIT(5),
	SILOFS_CTLF_INTERN  = SILOFS_BIT(6),
	SILOFS_CTLF_IDLE    = SILOFS_BIT(7),
};

#endif /* SILOFS_FLAGS_H_ */
