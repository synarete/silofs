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
#ifndef SILOFS_CCATTR_H_
#define SILOFS_CCATTR_H_

#if __has_attribute(__aligned__)
#define silofs_attr_aligned     __attribute__((__aligned__))
#define silofs_attr_alignedx(x) __attribute__((__aligned__(x)))
#define silofs_attr_aligned8    silofs_attr_alignedx(8)
#define silofs_attr_aligned16   silofs_attr_alignedx(16)
#define silofs_attr_aligned32   silofs_attr_alignedx(32)
#define silofs_attr_aligned64   silofs_attr_alignedx(64)
#else
#error "missing '__attribute__ ((__aligned__))'"
#endif

#if __has_attribute(__packed__)
#define silofs_attr_packed __attribute__((__packed__))
#else
#error "missing '__attribute__ ((__packed__))'"
#endif

#if __has_attribute(__noreturn__)
#define silofs_attr_noreturn __attribute__((__noreturn__))
#else
#error "missing '__attribute__ ((__noreturn__))'"
#endif

#if __has_attribute(__const__)
#define silofs_attr_const __attribute__((__const__))
#else
#define silofs_attr_const
#endif

#if __has_attribute(__format__)
#if defined(__clang__)
#define silofs_attr_printf(x_, y_) \
	__attribute__((__format__(__printf__, x_, y_)))
#elif defined(__GNUC__)
#define silofs_attr_printf(x_, y_) \
	__attribute__((__format__(gnu_printf, x_, y_)))
#else
#define silofs_attr_printf(x_, y_)
#endif
#else
#define silofs_attr_printf(x_, y_)
#endif

#if __has_attribute(__fallthrough__)
#define silofs_fallthrough __attribute__((__fallthrough__))
#else
#define silofs_fallthrough \
	do {               \
	} while (0) /* fallthrough */
#endif

#endif /* SILOFS_CCATTR_H_ */
