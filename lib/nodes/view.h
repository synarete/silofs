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
#ifndef SILOFS_VIEW_H_
#define SILOFS_VIEW_H_

#include <silofs/ondisk.h>
#include "addr.h"
#include "crypt.h"

struct silofs_view *silofs_view_new(struct silofs_alloc *alloc,
                                    enum silofs_mtype mtype, int flags);

void silofs_view_del(struct silofs_view *view, struct silofs_alloc *alloc,
                     enum silofs_mtype mtype, int flags);

void silofs_view_seal(struct silofs_view *view);

int silofs_view_verify(const struct silofs_view *view,
                       enum silofs_mtype         mtype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey  *ivkey,
                        const struct silofs_view   *view,
                        enum silofs_mtype mtype, void *ptr);

int silofs_decrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey  *ivkey,
                        const struct silofs_view   *view,
                        enum silofs_mtype mtype, void *ptr);

int silofs_decrypt_view_inplace(const struct silofs_cipher *cipher,
                                const struct silofs_ivkey  *ivkey,
                                struct silofs_view         *view,
                                enum silofs_mtype           mtype);

#endif /* SILOFS_VIEW_H_ */
