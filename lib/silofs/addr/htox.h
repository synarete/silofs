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
#ifndef SILOFS_HTOX_H_
#define SILOFS_HTOX_H_

#include <stdint.h>
#include <unistd.h>
#include <silofs/ondisk.h>

uint64_t silofs_u8b_as_u64(const uint8_t p[8]);

void silofs_u8b_from_u64(uint8_t p[8], uint64_t u);

uint16_t silofs_cpu_to_le16(uint16_t n);

uint16_t silofs_le16_to_cpu(uint16_t n);

uint32_t silofs_cpu_to_le32(uint32_t n);

uint32_t silofs_le32_to_cpu(uint32_t n);

uint64_t silofs_cpu_to_le64(uint64_t n);

uint64_t silofs_le64_to_cpu(uint64_t n);

uint64_t silofs_cpu_to_ino(ino_t ino);

ino_t silofs_ino_to_cpu(uint64_t ino);

int64_t silofs_cpu_to_off(off_t off);

off_t silofs_off_to_cpu(int64_t off);

uint64_t silofs_cpu_to_time(time_t tm);

time_t silofs_time_to_cpu(uint64_t tm);

void silofs_ts_to_cpu(const struct silofs_timespec *t, struct timespec *ts);

void silofs_cpu_to_ts(const struct timespec *ts, struct silofs_timespec *t);

#endif /* SILOFS_HTOX_H_ */
