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
#ifndef SILOFS_OFFLEN_H_
#define SILOFS_OFFLEN_H_

bool silofs_off_isnull(off_t off);

off_t silofs_off_min(off_t off1, off_t off2);

off_t silofs_off_max(off_t off1, off_t off2);

off_t silofs_off_max3(off_t off1, off_t off2, off_t off3);

off_t silofs_off_clamp(off_t off, off_t off_lo, off_t off_hi);

off_t silofs_off_end(off_t off, size_t len);

off_t silofs_off_align(off_t off, ssize_t align);

off_t silofs_off_next(off_t off, ssize_t len);

off_t silofs_off_remainder(off_t off, size_t len);

ssize_t silofs_off_diff(off_t beg, off_t end);

ssize_t silofs_off_len(off_t beg, off_t end);

bool silofs_off_within(off_t off, off_t beg, off_t end);

int silofs_verify_off(off_t off);

#endif /* SILOFS_OFFLEN_H_ */
