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
#ifndef SILOFS_HTOX_H_
#define SILOFS_HTOX_H_

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>

static inline uint16_t silofs_cpu_to_le16(uint16_t n)
{
	return htole16(n);
}

static inline uint16_t silofs_le16_to_cpu(uint16_t n)
{
	return le16toh(n);
}

static inline uint32_t silofs_cpu_to_le32(uint32_t n)
{
	return htole32(n);
}

static inline uint32_t silofs_le32_to_cpu(uint32_t n)
{
	return le32toh(n);
}

static inline uint64_t silofs_cpu_to_le64(uint64_t n)
{
	return htole64(n);
}

static inline uint64_t silofs_le64_to_cpu(uint64_t n)
{
	return le64toh(n);
}

static inline uint64_t silofs_cpu_to_ino(ino_t ino)
{
	return silofs_cpu_to_le64(ino);
}

static inline ino_t silofs_ino_to_cpu(uint64_t ino)
{
	return (ino_t)silofs_le64_to_cpu(ino);
}

static inline int64_t silofs_cpu_to_off(loff_t off)
{
	return (int64_t)silofs_cpu_to_le64((uint64_t)off);
}

static inline loff_t silofs_off_to_cpu(int64_t off)
{
	return (loff_t)silofs_le64_to_cpu((uint64_t)off);
}

static inline uint64_t silofs_cpu_to_time(time_t tm)
{
	return silofs_cpu_to_le64((uint64_t)tm);
}

static inline time_t silofs_time_to_cpu(uint64_t tm)
{
	return (time_t)silofs_le64_to_cpu(tm);
}

#endif /* SILOFS_HTOX_H_ */
