/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

#define silofs_aligned          __attribute__ ((__aligned__))
#define silofs_aligned8         __attribute__ ((__aligned__(8)))
#define silofs_aligned16        __attribute__ ((__aligned__(16)))
#define silofs_aligned32        __attribute__ ((__aligned__(32)))
#define silofs_aligned64        __attribute__ ((__aligned__(64)))
#define silofs_packed           __attribute__ ((__packed__))
#define silofs_packed_aligned   __attribute__ ((__packed__, __aligned__))
#define silofs_packed_aligned4  __attribute__ ((__packed__, __aligned__(4)))
#define silofs_packed_aligned8  __attribute__ ((__packed__, __aligned__(8)))
#define silofs_packed_aligned16 __attribute__ ((__packed__, __aligned__(16)))
#define silofs_packed_aligned32 __attribute__ ((__packed__, __aligned__(32)))
#define silofs_packed_aligned64 __attribute__ ((__packed__, __aligned__(64)))

#endif /* SILOFS_CCATTR_H_ */
