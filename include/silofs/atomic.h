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
#ifndef SILOFS_ATOMIC_H_
#define SILOFS_ATOMIC_H_

/* Atomic operations on integers with relaxed semantics */
#define SILOFS_ATOMIC_MODEL     __ATOMIC_SEQ_CST

static inline int silofs_atomic_get(const int *ptr)
{
	return __atomic_load_n(ptr, SILOFS_ATOMIC_MODEL);
}

static inline void silofs_atomic_set(int *ptr, int val)
{
	__atomic_store_n(ptr, val, SILOFS_ATOMIC_MODEL);
}

static inline void silofs_atomic_add(int *ptr, int val)
{
	__atomic_add_fetch(ptr, val, SILOFS_ATOMIC_MODEL);
}

static inline void silofs_atomic_sub(int *ptr, int val)
{
	__atomic_sub_fetch(ptr, val, SILOFS_ATOMIC_MODEL);
}

#endif /* SILOFS_ATOMIC_H_ */
