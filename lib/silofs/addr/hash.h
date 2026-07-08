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
#ifndef SILOFS_HASH_H_
#define SILOFS_HASH_H_

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

void silofs_hash256_assign(struct silofs_hash256       *hash,
                           const struct silofs_hash256 *other);

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256       *other);

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf        *out_name);

int silofs_hash256_to_str(const struct silofs_hash256 *hash, char *str,
                          size_t len);

int silofs_hash256_from_str(struct silofs_hash256 *hash, const char *str,
                            size_t len);

#endif /* SILOFS_HASH_H_ */
