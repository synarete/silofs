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
#include <silofs/configs.h>
#include <silofs/version.h>

#ifdef HAVE_CONFIG_H
#if !defined(SILOFS_VERSION_STRING)
#error "missing SILOFS_VERSION_STRING in config.h"
#endif
#if !defined(SILOFS_VERSION_MAJOR)
#error "missing SILOFS_VERSION_MAJOR in config.h"
#endif
#if !defined(SILOFS_VERSION_MINOR)
#error "missing SILOFS_VERSION_MINOR in config.h"
#endif
#if !defined(SILOFS_VERSION_SUBLEVEL)
#error "missing VERSION_SUBLEVEL in config.h"
#endif
#if !defined(SILOFS_RELEASE)
#error "missing RELEASE in config.h"
#endif
#if !defined(SILOFS_REVISION)
#error "missing REVISION in config.h"
#endif
#else
#define SILOFS_VERSION_STRING   "0"
#define SILOFS_VERSION_MAJOR    0
#define SILOFS_VERSION_MINOR    1
#define SILOFS_VERSION_SUBLEVEL 1
#define SILOFS_RELEASE          "0"
#define SILOFS_REVISION         "xxxxxxx"
#endif

#define SILOFS_VERSION_STRING_FULL \
        SILOFS_VERSION_STRING "-" SILOFS_RELEASE "." SILOFS_REVISION


const struct silofs_version silofs_version = {
	.string = SILOFS_VERSION_STRING_FULL,
	.major = SILOFS_VERSION_MAJOR,
	.minor = SILOFS_VERSION_MINOR,
	.sublevel = SILOFS_VERSION_SUBLEVEL
};

