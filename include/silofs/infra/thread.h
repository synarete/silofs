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
#ifndef SILOFS_THREAD_H_
#define SILOFS_THREAD_H_

#include <pthread.h>
#include <stdbool.h>

struct silofs_thread;

typedef int (*silofs_execute_fn)(struct silofs_thread *);

struct silofs_thread {
	pthread_t               pth;
	silofs_execute_fn       exec;
	void                   *arg;
	time_t                  start_time;
	time_t                  finish_time;
	int                     status;
	char                    name[84];
};

struct silofs_mutex {
	pthread_mutex_t         mutex;
};

struct silofs_cond {
	pthread_cond_t          cond;
};

struct silofs_rwlock {
	pthread_rwlock_t        rwlock;
};

struct silofs_muco {
	struct silofs_cond      co;
	struct silofs_mutex     mu;
	long flags;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_thread_sigblock_common(void);

int silofs_thread_create(struct silofs_thread *th, silofs_execute_fn exec,
                         void *arg, const char *name);

int silofs_thread_join(struct silofs_thread *th);


int silofs_mutex_init(struct silofs_mutex *mutex);

void silofs_mutex_fini(struct silofs_mutex *mutex);

void silofs_mutex_lock(struct silofs_mutex *mutex);

bool silofs_mutex_trylock(struct silofs_mutex *mutex);

bool silofs_mutex_timedlock(struct silofs_mutex *mutex,
                            const struct timespec *abstime);

void silofs_mutex_unlock(struct silofs_mutex *mutex);


int silofs_cond_init(struct silofs_cond *cond);

void silofs_cond_fini(struct silofs_cond *cond);

void silofs_cond_wait(struct silofs_cond *cond,
                      struct silofs_mutex *mutex);

int silofs_cond_timedwait(struct silofs_cond *cond, struct silofs_mutex *mutex,
                          const struct timespec *ts);

int silofs_cond_ntimedwait(struct silofs_cond *cond,
                           struct silofs_mutex *mutex, time_t nsec);

void silofs_cond_signal(struct silofs_cond *cond);

void silofs_cond_broadcast(struct silofs_cond *cond);


int silofs_rwlock_init(struct silofs_rwlock *rwlock);

void silofs_rwlock_fini(struct silofs_rwlock *rwlock);

void silofs_rwlock_rdlock(struct silofs_rwlock *rwlock);

bool silofs_rwlock_tryrdlock(struct silofs_rwlock *rwlock);

void silofs_rwlock_wrlock(struct silofs_rwlock *rwlock);

bool silofs_rwlock_trywrlock(struct silofs_rwlock *rwlock);

void silofs_rwlock_unlock(struct silofs_rwlock *rwlock);


int silofs_muco_init(struct silofs_muco *muco);

void silofs_muco_fini(struct silofs_muco *muco);

#endif /* SILOFS_THREAD_H_ */
