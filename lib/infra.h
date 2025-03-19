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
#ifndef SILOFS_INFRA_H_
#define SILOFS_INFRA_H_

#include <silofs/ccattr.h>
#include <silofs/consts.h>
#include <silofs/errors.h>
#include <silofs/macros.h>
#include <silofs/syscall.h>
#include <silofs/version.h>
#include <silofs/logging.h>
#include <silofs/panic.h>
#include <silofs/memalloc.h>
#include <silofs/random.h>
#include <silofs/thread.h>

#include "infra/utility.h"
#include "infra/atomic.h"
#include "infra/avl.h"
#include "infra/base64.h"
#include "infra/bytebuf.h"
#include "infra/hash.h"
#include "infra/iovec.h"
#include "infra/list.h"
#include "infra/pipe.h"
#include "infra/socket.h"
#include "infra/times.h"
#include "infra/qalloc.h"
#include "infra/zcmpr.h"

#ifdef SILOFS_USE_PRIVATE

#define likely(x_)   silofs_likely(x_)
#define unlikely(x_) silofs_unlikely(x_)

#define STATICASSERT(expr_)         SILOFS_STATICASSERT(expr_)
#define STATICASSERT_EQ(a_, b_)     SILOFS_STATICASSERT_EQ(a_, b_)
#define STATICASSERT_LT(a_, b_)     SILOFS_STATICASSERT_LT(a_, b_)
#define STATICASSERT_LE(a_, b_)     SILOFS_STATICASSERT_LE(a_, b_)
#define STATICASSERT_GT(a_, b_)     SILOFS_STATICASSERT_GT(a_, b_)
#define STATICASSERT_GE(a_, b_)     SILOFS_STATICASSERT_GE(a_, b_)
#define STATICASSERT_SIZEOF(t_, s_) SILOFS_STATICASSERT_EQ(sizeof(t_), s_)

#define ARRAY_SIZE(x)          SILOFS_ARRAY_SIZE(x)
#define container_of(p, t, m)  silofs_container_of(p, t, m)
#define container_of2(p, t, m) silofs_container_of2(p, t, m)
#define unconst(p)             silofs_unconst(p)
#define unused(x)              silofs_unused(x)

#define log_dbg(fmt, ...)  silofs_log_debug(fmt, __VA_ARGS__)
#define log_info(fmt, ...) silofs_log_info(fmt, __VA_ARGS__)
#define log_warn(fmt, ...) silofs_log_warn(fmt, __VA_ARGS__)
#define log_err(fmt, ...)  silofs_log_error(fmt, __VA_ARGS__)
#define log_crit(fmt, ...) silofs_log_crit(fmt, __VA_ARGS__)
#endif

#endif /* SILOFS_INFRA_H_ */
