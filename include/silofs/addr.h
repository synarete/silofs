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
#ifndef SILOFS_ADDR_H_
#define SILOFS_ADDR_H_

#include <silofs/defs.h>
#include <silofs/errors.h>
#include <silofs/flags.h>
#include <silofs/addr/offlba.h>
#include <silofs/addr/htox.h>
#include <silofs/addr/meta.h>
#include <silofs/addr/ivkey.h>
#include <silofs/addr/blobid.h>
#include <silofs/addr/oaddr.h>
#include <silofs/addr/ltype.h>
#include <silofs/addr/laddr.h>
#include <silofs/addr/uaddr.h>
#include <silofs/addr/vaddr.h>
#include <silofs/addr/caddr.h>
#include <silofs/addr/hmapq.h>

#ifdef SILOFS_HAVE_PRIVATE
#include <silofs/addr-private.h>
#endif

#endif /* SILOFS_ADDR_H_ */
