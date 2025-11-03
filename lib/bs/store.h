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
#ifndef SILOFS_STORE_H_
#define SILOFS_STORE_H_

#include "infra.h"
#include "addr.h"
#include "uber.h"
#include "env.h"

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_baddr *baddr,
                      struct silofs_ub_info **out_ubi);

#endif /* SILOFS_STORE_H_ */
