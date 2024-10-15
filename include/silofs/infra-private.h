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
#ifndef SILOFS_INFRA_PRIVATE_H_
#define SILOFS_INFRA_PRIVATE_H_

#ifndef SILOFS_HAVE_PRIVATE
#error "internal library header -- do not include!"
#endif

#include <silofs/infra.h>
#include <silofs/defs.h>

/* common macros */
#define likely(x_)                      silofs_likely(x_)
#define unlikely(x_)                    silofs_unlikely(x_)

#define STATICASSERT(expr_)             SILOFS_STATICASSERT(expr_)
#define STATICASSERT_EQ(a_, b_)         SILOFS_STATICASSERT_EQ(a_, b_)
#define STATICASSERT_LT(a_, b_)         SILOFS_STATICASSERT_LT(a_, b_)
#define STATICASSERT_LE(a_, b_)         SILOFS_STATICASSERT_LE(a_, b_)
#define STATICASSERT_GT(a_, b_)         SILOFS_STATICASSERT_GT(a_, b_)
#define STATICASSERT_GE(a_, b_)         SILOFS_STATICASSERT_GE(a_, b_)
#define STATICASSERT_SIZEOF(t_, s_)     SILOFS_STATICASSERT_EQ(sizeof(t_), s_)

/* aliases */
#define ARRAY_SIZE(x)                   SILOFS_ARRAY_SIZE(x)
#define container_of(p, t, m)           silofs_container_of(p, t, m)
#define container_of2(p, t, m)          silofs_container_of2(p, t, m)
#define unconst(p)                      silofs_unconst(p)
#define unused(x)                       silofs_unused(x)

#define min(x, y)                       silofs_min(x, y)
#define max(x, y)                       silofs_max(x, y)
#define div_round_up(n, d)              silofs_div_round_up(n, d)

#define log_dbg(fmt, ...)               silofs_log_debug(fmt, __VA_ARGS__)
#define log_info(fmt, ...)              silofs_log_info(fmt, __VA_ARGS__)
#define log_warn(fmt, ...)              silofs_log_warn(fmt, __VA_ARGS__)
#define log_err(fmt, ...)               silofs_log_error(fmt, __VA_ARGS__)
#define log_crit(fmt, ...)              silofs_log_crit(fmt, __VA_ARGS__)

#define list_head_init(lh)              silofs_list_head_init(lh)
#define list_head_initn(lh, n)          silofs_list_head_initn(lh, n)
#define list_head_fini(lh)              silofs_list_head_fini(lh)
#define list_head_finin(lh, n)          silofs_list_head_finin(lh, n)
#define list_head_remove(lh)            silofs_list_head_remove(lh)
#define list_head_insert_after(p, q)    silofs_list_head_insert_after(p, q)
#define list_head_insert_before(p, q)   silofs_list_head_insert_before(p, q)

#define list_init(ls)                   silofs_list_init(ls)
#define list_fini(ls)                   silofs_list_fini(ls)
#define list_isempty(ls)                silofs_list_isempty(ls)
#define list_push_back(ls, lh)          silofs_list_push_back(ls, lh)
#define list_push_front(ls, lh)         silofs_list_push_front(ls, lh)
#define list_pop_front(ls)              silofs_list_pop_front(ls)
#define list_front(ls)                  silofs_list_front(ls)

#define listq_init(lq)                  silofs_listq_init(lq)
#define listq_initn(lq, n)              silofs_listq_initn(lq, n)
#define listq_fini(lq)                  silofs_listq_fini(lq)
#define listq_finin(lq, n)              silofs_listq_finin(lq, n)
#define listq_size(lq)                  silofs_listq_size(lq)
#define listq_isempty(lq)               silofs_listq_isempty(lq)
#define listq_push_back(lq, lh)         silofs_listq_push_back(lq, lh)
#define listq_push_front(lq, lh)        silofs_listq_push_front(lq, lh)
#define listq_pop_back(lq)              silofs_listq_pop_back(lq)
#define listq_pop_front(lq)             silofs_listq_pop_front(lq)
#define listq_remove(lq, lh)            silofs_listq_remove(lq, lh)
#define listq_front(lq)                 silofs_listq_front(lq)
#define listq_back(lq)                  silofs_listq_back(lq)
#define listq_next(lq, lh)              silofs_listq_next(lq, lh)
#define listq_prev(lq, lh)              silofs_listq_prev(lq, lh)

#endif /* SILOFS_INFRA_PRIVATE_H_ */
