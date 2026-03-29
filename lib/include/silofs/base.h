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
#ifndef SILOFS_BASE_H_
#define SILOFS_BASE_H_

#include <silofs/ccattr.h>
#include <silofs/consts.h>
#include <silofs/errors.h>
#include <silofs/macros.h>
#include <silofs/syscall.h>
#include <silofs/version.h>
#include <silofs/logging.h>
#include <silofs/panic.h>
#include <silofs/memalloc.h>

#include <silofs/base/utility.h>
#include <silofs/base/atomic.h>
#include <silofs/base/avl.h>
#include <silofs/base/base64.h>
#include <silofs/base/bytebuf.h>
#include <silofs/base/hashfn.h>
#include <silofs/base/iovec.h>
#include <silofs/base/list.h>
#include <silofs/base/pipe.h>
#include <silofs/base/socket.h>
#include <silofs/base/snprintf.h>
#include <silofs/base/times.h>
#include <silofs/base/uuid.h>
#include <silofs/base/qalloc.h>
#include <silofs/base/uconv.h>
#include <silofs/base/zcmpr.h>
#include <silofs/base/thread.h>
#include <silofs/base/hamming.h>

#ifdef SILOFS_USE_PRIVATE
#include <silofs/base/private.h>
#endif

#endif /* SILOFS_BASE_H_ */
