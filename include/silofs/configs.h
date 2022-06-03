/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef HAVE_CONFIG_H
#error "HAVE_CONFIG_H is not defined"
#endif

#ifdef NULL
#error "<silofs/configs.h> must be included before system headers"
#endif

#ifdef SILOFS_STR
#error "<silofs/configs.h> must be included first"
#endif

#ifdef SILOFS_CONFIGS_ONCE
#error "<silofs/configs.h> must be included once"
#endif

#include "config.h"
#include "config-am.h"
#define SILOFS_CONFIGS_ONCE 1
