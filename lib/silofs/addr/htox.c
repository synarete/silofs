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
#include <silofs/configs.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>

#include <silofs/ondisk.h>
#include <silofs/addr.h>

uint64_t silofs_u8b_as_u64(const uint8_t p[8])
{
	uint64_t u = 0;

	u |= (uint64_t)(p[0]) << 56;
	u |= (uint64_t)(p[1]) << 48;
	u |= (uint64_t)(p[2]) << 40;
	u |= (uint64_t)(p[3]) << 32;
	u |= (uint64_t)(p[4]) << 24;
	u |= (uint64_t)(p[5]) << 16;
	u |= (uint64_t)(p[6]) << 8;
	u |= (uint64_t)(p[7]);

	return u;
}

void silofs_u8b_from_u64(uint8_t p[8], uint64_t u)
{
	p[0] = (uint8_t)(u >> 56);
	p[1] = (uint8_t)(u >> 48);
	p[2] = (uint8_t)(u >> 40);
	p[3] = (uint8_t)(u >> 32);
	p[4] = (uint8_t)(u >> 24);
	p[5] = (uint8_t)(u >> 16);
	p[6] = (uint8_t)(u >> 8);
	p[7] = (uint8_t)(u);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint16_t silofs_cpu_to_le16(uint16_t n)
{
	return htole16(n);
}

uint16_t silofs_le16_to_cpu(uint16_t n)
{
	return le16toh(n);
}

uint32_t silofs_cpu_to_le32(uint32_t n)
{
	return htole32(n);
}

uint32_t silofs_le32_to_cpu(uint32_t n)
{
	return le32toh(n);
}

uint64_t silofs_cpu_to_le64(uint64_t n)
{
	return htole64(n);
}

uint64_t silofs_le64_to_cpu(uint64_t n)
{
	return le64toh(n);
}

uint64_t silofs_cpu_to_ino(ino_t ino)
{
	return silofs_cpu_to_le64(ino);
}

ino_t silofs_ino_to_cpu(uint64_t ino)
{
	return (ino_t)silofs_le64_to_cpu(ino);
}

int64_t silofs_cpu_to_off(off_t off)
{
	return (int64_t)silofs_cpu_to_le64((uint64_t)off);
}

off_t silofs_off_to_cpu(int64_t off)
{
	return (off_t)silofs_le64_to_cpu((uint64_t)off);
}

uint64_t silofs_cpu_to_time(time_t tm)
{
	return silofs_cpu_to_le64((uint64_t)tm);
}

time_t silofs_time_to_cpu(uint64_t tm)
{
	return (time_t)silofs_le64_to_cpu(tm);
}

void silofs_ts_to_cpu(const struct silofs_timespec *t, struct timespec *ts)
{
	ts->tv_sec  = (time_t)silofs_le64_to_cpu(t->t_sec);
	ts->tv_nsec = (long)silofs_le64_to_cpu(t->t_nsec);
}

void silofs_cpu_to_ts(const struct timespec *ts, struct silofs_timespec *t)
{
	t->t_sec  = silofs_cpu_to_le64((uint64_t)ts->tv_sec);
	t->t_nsec = silofs_cpu_to_le64((uint64_t)ts->tv_nsec);
}
