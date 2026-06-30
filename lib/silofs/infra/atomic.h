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
#ifndef SILOFS_ATOMIC_H_
#define SILOFS_ATOMIC_H_

#include <stdatomic.h>

#define silofs_atomic _Atomic

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline int silofs_atomic_get(const int *ptr)
{
	return __atomic_load_n(ptr, memory_order_acquire);
}

static inline void silofs_atomic_set(int *ptr, int val)
{
	__atomic_store_n(ptr, val, memory_order_release);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline int silofs_atomic_rlx_get(const int *ptr)
{
	return __atomic_load_n(ptr, memory_order_relaxed);
}

static inline void silofs_atomic_rlx_set(int *ptr, int val)
{
	__atomic_store_n(ptr, val, memory_order_relaxed);
}

static inline int silofs_atomic_rlx_add(int *ptr, int val)
{
	return __atomic_add_fetch(ptr, val, memory_order_relaxed);
}

static inline int silofs_atomic_rlx_sub(int *ptr, int val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_relaxed);
}

static inline long silofs_atomic_rlx_getl(const long *ptr)
{
	return __atomic_load_n(ptr, memory_order_relaxed);
}

static inline void silofs_atomic_rlx_setl(long *ptr, long val)
{
	__atomic_store_n(ptr, val, memory_order_relaxed);
}

static inline long silofs_atomic_rlx_addl(long *ptr, long val)
{
	return __atomic_add_fetch(ptr, val, memory_order_relaxed);
}

static inline long silofs_atomic_rlx_subl(long *ptr, long val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_relaxed);
}

static inline unsigned long silofs_atomic_rlx_getul(const unsigned long *ptr)
{
	return __atomic_load_n(ptr, memory_order_relaxed);
}

static inline void
silofs_atomic_rlx_setul(unsigned long *ptr, unsigned long val)
{
	__atomic_store_n(ptr, val, memory_order_relaxed);
}

static inline unsigned long
silofs_atomic_rlx_addul(unsigned long *ptr, unsigned long val)
{
	return __atomic_add_fetch(ptr, val, memory_order_relaxed);
}

static inline unsigned long
silofs_atomic_rlx_subul(unsigned long *ptr, unsigned long val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_relaxed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline int silofs_atomic_sqc_get(const int *ptr)
{
	return __atomic_load_n(ptr, memory_order_seq_cst);
}

static inline void silofs_atomic_sqc_set(int *ptr, int val)
{
	__atomic_store_n(ptr, val, memory_order_seq_cst);
}

static inline int silofs_atomic_sqc_add(int *ptr, int val)
{
	return __atomic_add_fetch(ptr, val, memory_order_seq_cst);
}

static inline int silofs_atomic_sqc_sub(int *ptr, int val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_seq_cst);
}

static inline long silofs_atomic_sqc_getl(const long *ptr)
{
	return __atomic_load_n(ptr, memory_order_seq_cst);
}

static inline void silofs_atomic_sqc_setl(long *ptr, long val)
{
	__atomic_store_n(ptr, val, memory_order_seq_cst);
}

static inline long silofs_atomic_sqc_addl(long *ptr, long val)
{
	return __atomic_add_fetch(ptr, val, memory_order_seq_cst);
}

static inline long silofs_atomic_sqc_subl(long *ptr, long val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_seq_cst);
}

static inline unsigned long silofs_atomic_sqc_getul(const unsigned long *ptr)
{
	return __atomic_load_n(ptr, memory_order_seq_cst);
}

static inline void
silofs_atomic_sqc_setul(unsigned long *ptr, unsigned long val)
{
	__atomic_store_n(ptr, val, memory_order_seq_cst);
}

static inline unsigned long
silofs_atomic_sqc_addul(unsigned long *ptr, unsigned long val)
{
	return __atomic_add_fetch(ptr, val, memory_order_seq_cst);
}

static inline unsigned long
silofs_atomic_sqc_subul(unsigned long *ptr, unsigned long val)
{
	return __atomic_sub_fetch(ptr, val, memory_order_seq_cst);
}

#endif /* SILOFS_ATOMIC_H_ */
