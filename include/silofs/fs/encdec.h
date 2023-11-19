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
#ifndef SILOFS_ENCDEC_H_
#define SILOFS_ENCDEC_H_

int silofs_encrypt_view(const struct silofs_fsenv *fsenv,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *seediv,
                        const struct silofs_view *view, void *ptr);

int silofs_decrypt_ui_view(const struct silofs_fsenv *fsenv,
                           struct silofs_unode_info *ui);

int silofs_decrypt_vi_view(const struct silofs_fsenv *fsenv,
                           struct silofs_vnode_info *vi);

#endif /* SILOFS_ENCDEC_H_ */
