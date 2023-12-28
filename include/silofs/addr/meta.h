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
#ifndef SILOFS_META_H_
#define SILOFS_META_H_

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t type, size_t size);

void silofs_hdr_seal(struct silofs_header *hdr);

int silofs_hdr_verify(const struct silofs_header *hdr,
                      uint8_t expected_type, size_t expected_size);

#endif /* SILOFS_META_H_ */
