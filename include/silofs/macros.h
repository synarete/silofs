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
#ifndef SILOFS_MACROS_H_
#define SILOFS_MACROS_H_

#include <stddef.h>

/* stringify macros */
#define SILOFS_STR(x_)          SILOFS_MAKESTR_(x_)
#define SILOFS_MAKESTR_(x_)     #x_
#define SILOFS_CONCAT(x_, y_)   x_ ## y_

/* file line pair */
#define SILOFS_FL_LN_           __FILE__, __LINE__

/* array number of elements */
#define SILOFS_ARRAY_SIZE(x_)   ( (sizeof((x_))) / (sizeof(((x_)[0]))) )

/* utility macros */
#define SILOFS_CONTAINER_OF(ptr_, type_, member_) \
	(type_ *)((void *)((char *)ptr_ - offsetof(type_, member_)))

#define SILOFS_CONTAINER_OF2(ptr_, type_, member_) \
	(const type_ *)((const void *) \
	                ((const char *)ptr_ - offsetof(type_, member_)))

#define silofs_container_of(ptr_, type_, member_) \
	SILOFS_CONTAINER_OF(ptr_, type_, member_)

#define silofs_container_of2(ptr_, type_, member_) \
	SILOFS_CONTAINER_OF2(ptr_, type_, member_)

#define silofs_unused(x_)       ((void)x_)

/* numeric operations */
#define SILOFS_DIV_ROUND_UP(n, d)       ((n + d - 1) / d)
#define SILOFS_ROUND_TO(n, k)           (SILOFS_DIV_ROUND_UP(n, k) * k)
#define SILOFS_BIT(n)                   (1 << n)

/* branch-predictor helpers */
#define silofs_likely(x_)               __builtin_expect(!!(x_), 1)
#define silofs_unlikely(x_)             __builtin_expect(!!(x_), 0)

/* unreachable code marker */
#define silofs_unreachable()            __builtin_unreachable()

/* compile-time assertions */
#define SILOFS_STATICASSERT(expr_)       _Static_assert(expr_, #expr_)
#define SILOFS_STATICASSERT_EQ(a_, b_)   SILOFS_STATICASSERT(a_ == b_)
#define SILOFS_STATICASSERT_LE(a_, b_)   SILOFS_STATICASSERT(a_ <= b_)
#define SILOFS_STATICASSERT_LT(a_, b_)   SILOFS_STATICASSERT(a_ < b_)
#define SILOFS_STATICASSERT_GE(a_, b_)   SILOFS_STATICASSERT(a_ >= b_)
#define SILOFS_STATICASSERT_GT(a_, b_)   SILOFS_STATICASSERT(a_ > b_)

#endif /* SILOFS_MACROS_H_ */
