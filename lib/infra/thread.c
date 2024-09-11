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
#include <silofs/configs.h>
#include <silofs/macros.h>
#include <silofs/syscall.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/panic.h>
#include <silofs/infra/time.h>
#include <silofs/infra/thread.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#if defined(NDEBUG)
#define SILOFS_MUTEX_KIND PTHREAD_MUTEX_NORMAL
#else
#define SILOFS_MUTEX_KIND PTHREAD_MUTEX_ERRORCHECK
#endif

int silofs_thread_sigblock_common(void)
{
	sigset_t sigset_th;

	sigemptyset(&sigset_th);
	sigaddset(&sigset_th, SIGHUP);
	sigaddset(&sigset_th, SIGINT);
	sigaddset(&sigset_th, SIGQUIT);
	sigaddset(&sigset_th, SIGTERM);
	sigaddset(&sigset_th, SIGTRAP);
	sigaddset(&sigset_th, SIGUSR1);
	sigaddset(&sigset_th, SIGUSR2);
	sigaddset(&sigset_th, SIGPIPE);
	sigaddset(&sigset_th, SIGALRM);
	sigaddset(&sigset_th, SIGCHLD);
	sigaddset(&sigset_th, SIGURG);
	sigaddset(&sigset_th, SIGPROF);
	sigaddset(&sigset_th, SIGWINCH);
	sigaddset(&sigset_th, SIGIO);

	return pthread_sigmask(SIG_BLOCK, &sigset_th, NULL);
}

static void silofs_thread_prepare(struct silofs_thread *th)
{
	th->start_time = silofs_time_now_monotonic();
	if (strlen(th->name)) {
		pthread_setname_np(th->pth, th->name);
	}
}

static void silofs_thread_complete(struct silofs_thread *th, int err)
{
	th->status = err;
	th->finish_time = silofs_time_now_monotonic();
}

static void silofs_thread_exit(struct silofs_thread *th)
{
	pthread_exit(th);
}

static void *silofs_thread_start(void *arg)
{
	struct silofs_thread *th = (struct silofs_thread *)arg;
	int err;

	silofs_thread_prepare(th);
	err = th->exec(th);
	silofs_thread_complete(th, err);
	silofs_thread_exit(th);
	return th; /* should not get here */
}

int silofs_thread_create(struct silofs_thread *th, silofs_execute_fn exec,
                         void *arg, const char *name)
{
	pthread_attr_t attr;
	size_t nlen = 0;
	int err;

	if (exec == NULL) {
		return -EINVAL;
	}
	err = pthread_attr_init(&attr);
	if (err) {
		return err;
	}

	memset(th, 0, sizeof(*th));
	th->start_time = 0;
	th->finish_time = 0;
	th->status = 0;
	th->exec = exec;
	th->arg = arg;
	if (name != NULL) {
		nlen = silofs_min(strlen(name), sizeof(th->name) - 1);
		memcpy(th->name, name, nlen);
	}

	err = pthread_create(&th->pth, &attr, silofs_thread_start, th);
	pthread_attr_destroy(&attr);

	return err;
}

int silofs_thread_join(struct silofs_thread *th)
{
	return pthread_join(th->pth, NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int silofs_pthread_err(int err, const char *func)
{
#if !defined(NDEBUG)
	if (err) {
		silofs_panic("%s: %d", func, err);
	}
#else
	silofs_unused(func);
#endif
	return -abs(err);
}

int silofs_mutex_init(struct silofs_mutex *mutex)
{
	pthread_mutexattr_t attr;
	int err;

	err = pthread_mutexattr_init(&attr);
	if (err) {
		return silofs_pthread_err(err, "pthread_mutexattr_init");
	}
	err = pthread_mutexattr_settype(&attr, SILOFS_MUTEX_KIND);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		return silofs_pthread_err(err, "pthread_mutexattr_settype");
	}
	err = pthread_mutex_init(&mutex->mutex, &attr);
	if (err) {
		pthread_mutexattr_destroy(&attr);
		return silofs_pthread_err(err, "pthread_mutex_init");
	}
	err = pthread_mutexattr_destroy(&attr);
	if (err) {
		pthread_mutex_destroy(&mutex->mutex);
		return silofs_pthread_err(err, "pthread_mutexattr_destroy");
	}
	return 0;
}

void silofs_mutex_fini(struct silofs_mutex *mutex)
{
	int err;

	err = pthread_mutex_destroy(&mutex->mutex);
	if (err) {
		silofs_panic("pthread_mutex_destroy: %d", err);
	}
}

void silofs_mutex_lock(struct silofs_mutex *mutex)
{
	int err;

	err = pthread_mutex_lock(&mutex->mutex);
	if (err) {
		silofs_panic("pthread_mutex_lock: %d", err);
	}
}

bool silofs_mutex_trylock(struct silofs_mutex *mutex)
{
	int err;
	bool status = false;

	err = pthread_mutex_trylock(&mutex->mutex);
	if (err == 0) {
		status = true;
	} else if (err == EBUSY) {
		status = false;
	} else {
		silofs_panic("pthread_mutex_trylock: %d", err);
	}
	return status;
}

bool silofs_mutex_timedlock(struct silofs_mutex *mutex,
                            const struct timespec *abstime)
{
	int err;
	bool status = false;

	err = pthread_mutex_timedlock(&mutex->mutex, abstime);
	if (err == 0) {
		status = true;
	} else if (err == ETIMEDOUT) {
		status = false;
	} else {
		silofs_panic("pthread_mutex_timedlock: %d", err);
	}
	return status;
}

void silofs_mutex_unlock(struct silofs_mutex *mutex)
{
	int err;

	err = pthread_mutex_unlock(&mutex->mutex);
	if (err) {
		silofs_panic("pthread_mutex_unlock: %d", err);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_cond_init(struct silofs_cond *cond)
{
	pthread_condattr_t attr;
	int err;

	err = pthread_condattr_init(&attr);
	if (err) {
		return silofs_pthread_err(err, "pthread_condattr_init");
	}
	err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (err) {
		pthread_condattr_destroy(&attr);
		return silofs_pthread_err(err, "pthread_condattr_setclock");
	}
	err = pthread_cond_init(&cond->cond, &attr);
	if (err) {
		pthread_condattr_destroy(&attr);
		return silofs_pthread_err(err, "pthread_cond_init");
	}
	err = pthread_condattr_destroy(&attr);
	if (err) {
		pthread_cond_destroy(&cond->cond);
		return silofs_pthread_err(err, "pthread_condattr_destroy");
	}
	return 0;
}

void silofs_cond_fini(struct silofs_cond *cond)
{
	int err;

	err = pthread_cond_destroy(&cond->cond);
	if (err) {
		silofs_panic("pthread_cond_destroy: %d", err);
	}
}

void silofs_cond_wait(struct silofs_cond *cond, struct silofs_mutex *mutex)
{
	int err;

	err = pthread_cond_wait(&cond->cond, &mutex->mutex);
	if (err) {
		silofs_panic("pthread_cond_wait: %d", err);
	}
}

int silofs_cond_timedwait(struct silofs_cond *cond, struct silofs_mutex *mutex,
                          const struct timespec *ts)
{
	int err;

	err = pthread_cond_timedwait(&cond->cond, &mutex->mutex, ts);
	if (err && (err != ETIMEDOUT) && (err != EINTR)) {
		silofs_panic("pthread_cond_timedwait: %d", err);
	}
	return -err;
}

int silofs_cond_ntimedwait(struct silofs_cond *cond,
                           struct silofs_mutex *mutex, time_t nsec)
{
	struct timespec ts;

	silofs_mclock_now(&ts);
	ts.tv_sec += nsec;
	return silofs_cond_timedwait(cond, mutex, &ts);
}

void silofs_cond_signal(struct silofs_cond *cond)
{
	int err;

	err = pthread_cond_signal(&cond->cond);
	if (err) {
		silofs_panic("pthread_cond_signal: %d", err);
	}
}

void silofs_cond_broadcast(struct silofs_cond *cond)
{
	int err;

	err = pthread_cond_broadcast(&cond->cond);
	if (err) {
		silofs_panic("pthread_cond_broadcast: %d", err);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_rwlock_init(struct silofs_rwlock *rwlock)
{
	pthread_rwlockattr_t attr;
	int err;

	err = pthread_rwlockattr_init(&attr);
	if (err) {
		return silofs_pthread_err(err, "pthread_rwlockattr_init");
	}
	err = pthread_rwlock_init(&rwlock->rwlock, &attr);
	if (err) {
		pthread_rwlockattr_destroy(&attr);
		return silofs_pthread_err(err, "pthread_rwlock_init");
	}
	err = pthread_rwlockattr_destroy(&attr);
	if (err) {
		pthread_rwlock_destroy(&rwlock->rwlock);
		return silofs_pthread_err(err, "pthread_rwlockattr_destroy");
	}
	return 0;
}

void silofs_rwlock_fini(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_destroy(&rwlock->rwlock);
	if (err) {
		silofs_panic("pthread_rwlock_destroy: %d", err);
	}
}

void silofs_rwlock_rdlock(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_rdlock(&rwlock->rwlock);
	if (err) {
		silofs_panic("pthread_rwlock_rdlock: %d", err);
	}
}

bool silofs_rwlock_tryrdlock(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_tryrdlock(&rwlock->rwlock);
	if (err && (err != EBUSY)) {
		silofs_panic("pthread_rwlock_tryrdlock: %d", err);
	}
	return (err == 0);
}

void silofs_rwlock_wrlock(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_wrlock(&rwlock->rwlock);
	if (err) {
		silofs_panic("pthread_rwlock_wrlock: %d", err);
	}
}

bool silofs_rwlock_trywrlock(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_trywrlock(&rwlock->rwlock);
	if (err && (err != EBUSY)) {
		silofs_panic("pthread_rwlock_trywrlock: %d", err);
	}
	return (err == 0);
}

void silofs_rwlock_unlock(struct silofs_rwlock *rwlock)
{
	int err;

	err = pthread_rwlock_unlock(&rwlock->rwlock);
	if (err) {
		silofs_panic("silofs_rwlock_unlock: %d", err);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define SILOFS_MUCOF_INIT       (1L)

int silofs_muco_init(struct silofs_muco *mocu)
{
	int err;

	memset(mocu, 0, sizeof(*mocu));
	err = silofs_cond_init(&mocu->co);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&mocu->mu);
	if (err) {
		silofs_cond_fini(&mocu->co);
		return err;
	}
	mocu->flags |= SILOFS_MUCOF_INIT;
	return 0;
}

void silofs_muco_fini(struct silofs_muco *mocu)
{
	if (mocu->flags & SILOFS_MUCOF_INIT) {
		silofs_mutex_fini(&mocu->mu);
		silofs_cond_fini(&mocu->co);
		mocu->flags &= ~SILOFS_MUCOF_INIT;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void burnstack_recursively(int depth, int nbytes)
{
	char buf[512];
	const int cnt = silofs_min32((int)sizeof(buf), nbytes);

	if (cnt > 0) {
		memset(buf, 0xF4 ^ depth, (size_t)cnt);
		burnstack_recursively(depth + 1, nbytes - cnt);
	}
}

void silofs_burnstackn(int n)
{
	burnstack_recursively(0, n);
}

void silofs_burnstack(void)
{
	silofs_burnstackn((int)silofs_sc_page_size());
}
