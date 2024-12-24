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
#ifndef SILOFS_OFFLBA_H_
#define SILOFS_OFFLBA_H_

#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>

typedef loff_t silofs_lba_t;

bool silofs_off_isnull(loff_t off);

loff_t silofs_off_min(loff_t off1, loff_t off2);

loff_t silofs_off_max(loff_t off1, loff_t off2);

loff_t silofs_off_end(loff_t off, size_t len);

loff_t silofs_off_align(loff_t off, ssize_t align);

loff_t silofs_off_align_to_lbk(loff_t off);

loff_t silofs_off_next(loff_t off, ssize_t len);

ssize_t silofs_off_diff(loff_t beg, loff_t end);

ssize_t silofs_off_len(loff_t beg, loff_t end);

size_t silofs_off_ulen(loff_t beg, loff_t end);

silofs_lba_t silofs_off_to_lba(loff_t off);

loff_t silofs_off_in_lbk(loff_t off);

loff_t silofs_off_next_lbk(loff_t off);

loff_t silofs_off_remainder(loff_t off, size_t len);

int silofs_verify_off(loff_t off);

bool silofs_lba_isnull(silofs_lba_t lba);

loff_t silofs_lba_to_off(silofs_lba_t lba);

#endif /* SILOFS_OFFLBA_H_ */
