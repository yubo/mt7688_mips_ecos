/*
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/time.h>
#include <sys/types.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>

#include "traffic/trafficd.h"
#include "libubox/uloop.h"
#include "libubox/utils.h"


#ifdef USE_KQUEUE
#include <sys/event.h>
#endif
#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif
#ifdef USE_SELECT
#include <sys/select.h>
#else
#include <poll.h>
#include <sys/wait.h>
#endif


struct uloop_fd_event {
	struct uloop_fd *fd;
	unsigned int events;
};

struct uloop_fd_stack {
	struct uloop_fd_stack *next;
	struct uloop_fd *fd;
	unsigned int events;
};


static struct uloop_fd_stack *fd_stack = NULL;

#define ULOOP_MAX_EVENTS 10


static struct list_head timeouts = LIST_HEAD_INIT(timeouts);
static struct list_head processes = LIST_HEAD_INIT(processes);

static int poll_fd = -1;
bool uloop_cancelled = false;
bool uloop_handle_sigchld = true;
static bool do_sigchld = false;

static struct uloop_fd_event cur_fds[ULOOP_MAX_EVENTS];
static int cur_fd, cur_nfds;

#ifdef USE_KQUEUE

int uloop_init(void)
{
	struct timespec timeout = { 0, 0 };
	struct kevent ev = {};

	if (poll_fd >= 0)
		return 0;

	poll_fd = kqueue();
	if (poll_fd < 0)
		return -1;

	EV_SET(&ev, SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	kevent(poll_fd, &ev, 1, NULL, 0, &timeout);

	return 0;
}


static uint16_t get_flags(unsigned int flags, unsigned int mask)
{
	uint16_t kflags = 0;

	if (!(flags & mask))
		return EV_DELETE;

	kflags = EV_ADD;
	if (flags & ULOOP_EDGE_TRIGGER)
		kflags |= EV_CLEAR;

	return kflags;
}

static struct kevent events[ULOOP_MAX_EVENTS];

static int register_kevent(struct uloop_fd *fd, unsigned int flags)
{
	struct timespec timeout = { 0, 0 };
	struct kevent ev[2];
	int nev = 0;
	unsigned int fl = 0;
	unsigned int changed;
	uint16_t kflags;

	if (flags & ULOOP_EDGE_DEFER)
		flags &= ~ULOOP_EDGE_TRIGGER;

	changed = flags ^ fd->flags;
	if (changed & ULOOP_EDGE_TRIGGER)
		changed |= flags;

	if (changed & ULOOP_READ) {
		kflags = get_flags(flags, ULOOP_READ);
		EV_SET(&ev[nev++], fd->fd, EVFILT_READ, kflags, 0, 0, fd);
	}

	if (changed & ULOOP_WRITE) {
		kflags = get_flags(flags, ULOOP_WRITE);
		EV_SET(&ev[nev++], fd->fd, EVFILT_WRITE, kflags, 0, 0, fd);
	}

	if (!flags)
		fl |= EV_DELETE;

	fd->flags = flags;
	if (kevent(poll_fd, ev, nev, NULL, fl, &timeout) == -1)
		return -1;

	return 0;
}

static int register_poll(struct uloop_fd *fd, unsigned int flags)
{
	if (flags & ULOOP_EDGE_TRIGGER)
		flags |= ULOOP_EDGE_DEFER;
	else
		flags &= ~ULOOP_EDGE_DEFER;

	return register_kevent(fd, flags);
}

static int __uloop_fd_delete(struct uloop_fd *fd)
{
	return register_poll(fd, 0);
}

static int uloop_fetch_events(int timeout)
{
	struct timespec ts;
	int nfds, n;

	if (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
	}

	nfds = kevent(poll_fd, NULL, 0, events, ARRAY_SIZE(events), timeout >= 0 ? &ts : NULL);
	for (n = 0; n < nfds; n++) {
		struct uloop_fd_event *cur = &cur_fds[n];
		struct uloop_fd *u = events[n].udata;
		unsigned int ev = 0;

		cur->fd = u;
		if (!u)
			continue;

		if (events[n].flags & EV_ERROR) {
			u->error = true;
			if (!(u->flags & ULOOP_ERROR_CB))
				uloop_fd_delete(u);
		}

		if(events[n].filter == EVFILT_READ)
			ev |= ULOOP_READ;
		else if (events[n].filter == EVFILT_WRITE)
			ev |= ULOOP_WRITE;

		if (events[n].flags & EV_EOF)
			u->eof = true;
		else if (!ev)
			cur->fd = NULL;

		cur->events = ev;
		if (u->flags & ULOOP_EDGE_DEFER) {
			u->flags &= ~ULOOP_EDGE_DEFER;
			u->flags |= ULOOP_EDGE_TRIGGER;
			register_kevent(u, u->flags);
		}
	}
	return nfds;
}

#endif

#ifdef USE_EPOLL

/**
 * FIXME: uClibc < 0.9.30.3 does not define EPOLLRDHUP for Linux >= 2.6.17
 */
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

int uloop_init(void)
{
	if (poll_fd >= 0)
		return 0;

	poll_fd = epoll_create(32);
	if (poll_fd < 0)
		return -1;

	fcntl(poll_fd, F_SETFD, fcntl(poll_fd, F_GETFD) | FD_CLOEXEC);
	return 0;
}

static int register_poll(struct uloop_fd *fd, unsigned int flags)
{
	struct epoll_event ev;
	int op = fd->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

	memset(&ev, 0, sizeof(struct epoll_event));

	if (flags & ULOOP_READ)
		ev.events |= EPOLLIN | EPOLLRDHUP;

	if (flags & ULOOP_WRITE)
		ev.events |= EPOLLOUT;

	if (flags & ULOOP_EDGE_TRIGGER)
		ev.events |= EPOLLET;

	ev.data.fd = fd->fd;
	ev.data.ptr = fd;
	fd->flags = flags;

	return epoll_ctl(poll_fd, op, fd->fd, &ev);
}

static struct epoll_event events[ULOOP_MAX_EVENTS];

static int __uloop_fd_delete(struct uloop_fd *sock)
{
	sock->flags = 0;
	return epoll_ctl(poll_fd, EPOLL_CTL_DEL, sock->fd, 0);
}

static int uloop_fetch_events(int timeout)
{
	int n, nfds;

	nfds = epoll_wait(poll_fd, events, ARRAY_SIZE(events), timeout);
	for (n = 0; n < nfds; ++n) {
		struct uloop_fd_event *cur = &cur_fds[n];
		struct uloop_fd *u = events[n].data.ptr;
		unsigned int ev = 0;

		cur->fd = u;
		if (!u)
			continue;

		if (events[n].events & (EPOLLERR|EPOLLHUP)) {
			u->error = true;
			if (!(u->flags & ULOOP_ERROR_CB))
				uloop_fd_delete(u);
		}

		if(!(events[n].events & (EPOLLRDHUP|EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP))) {
			cur->fd = NULL;
			continue;
		}

		if(events[n].events & EPOLLRDHUP)
			u->eof = true;

		if(events[n].events & EPOLLIN)
			ev |= ULOOP_READ;

		if(events[n].events & EPOLLOUT)
			ev |= ULOOP_WRITE;

		cur->events = ev;
	}

	return nfds;
}

#endif

#ifdef USE_SELECT

#define ULOOP_NALLOC 16  /* for select/ecos */

static struct {
	fd_set rfds;
	fd_set wfds;
	fd_set *rd;
	fd_set *wr;
	int maxfd;
	int size;
	int max_size;
	struct uloop_fd_event *es;
} s;



int uloop_init(void)
{
	int i;

	if (poll_fd >= 0)
		return 0;

	s.size = ULOOP_NALLOC;
	s.max_size = FD_SETSIZE;
	s.es = malloc(s.size * sizeof(struct uloop_fd_event));
	for(i = 0; i < s.size; i++){
		s.es[i].fd = NULL;
		s.es[i].events = 0;
	}
	poll_fd = 1;
	return 0;
}


static int register_poll(struct uloop_fd *fd, unsigned int flags)
{
	int i;
	struct uloop_fd_event *es;
	if(fd->registered){
		for(i = 0; i < s.size; i++){
			if(fd == s.es[i].fd){
				//found !
				s.es[i].events = flags;
				return 0;
			}
		}
	}
	/* continue find */
	for(i = 0; i < s.size; i++){
		if(s.es[i].events == 0){
			s.es[i].fd = fd;
			s.es[i].events = flags;
			return 0;
		}
	}
	/* alloc */
	if(s.size + ULOOP_NALLOC > s.max_size){
		return -1;
	}

	es = realloc(s.es, (s.size + ULOOP_NALLOC)*sizeof(struct uloop_fd_event));
	if(!es)
		return -1;
	else
		s.es = es;
	for(i = s.size; i < s.size + ULOOP_NALLOC; i++){
		s.es[i].fd = NULL;
		s.es[i].events = 0;
	}
	s.es[s.size].fd = fd;
	s.es[s.size].events = flags;
	s.size += ULOOP_NALLOC;
	return 0;
}


static int __uloop_fd_delete(struct uloop_fd *sock)
{
	int i;

	for(i = 0; i < s.size; i++){
		if(s.es[i].fd == sock){
			s.es[i].fd = NULL;
			s.es[i].events = 0;
			return 0;
		}
	}
	return -1;
}

static int uloop_fetch_events(int timeout)
{
	int i, n, nfds;
	int found_read_event = 0;
	int found_write_event = 0;
	struct timeval tv;
	struct uloop_fd_event *cur;
	struct uloop_fd *u;
	unsigned int ev;

	if (timeout >= 0) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}

	s.maxfd = -1;
	FD_ZERO(&s.rfds);
	FD_ZERO(&s.wfds);

	for(i = 0; i < s.size; i++){
		if(!s.es[i].fd)
			continue;
		if(s.es[i].events & ULOOP_READ){
			found_read_event = 1;
			FD_SET(s.es[i].fd->fd, &s.rfds);
		}
		if(s.es[i].events & ULOOP_WRITE){
			found_write_event = 1;
			FD_SET(s.es[i].fd->fd, &s.wfds);
		}
		if(s.es[i].fd->fd > s.maxfd)
			s.maxfd = s.es[i].fd->fd;
	}

	if(found_read_event)
		s.rd = &s.rfds;
	else
		s.rd = NULL;

	if(found_write_event)
		s.wr = &s.wfds;
	else
		s.wr = NULL;


	nfds = select(s.maxfd + 1, s.rd, s.wr, NULL, timeout >= 0 ? &tv : NULL);

	for(i = 0, n = 0; i < s.size; i++){
		if(!s.es[i].fd)
			continue;

		u = NULL;
		ev = 0;
		if((s.es[i].events & ULOOP_READ) &&
				FD_ISSET(s.es[i].fd->fd, &s.rfds)){
			u = s.es[i].fd;
			ev |= ULOOP_READ;
		}
		if((s.es[i].events & ULOOP_WRITE) &&
				FD_ISSET(s.es[i].fd->fd, &s.wfds)){
			u = s.es[i].fd;
			ev |= ULOOP_WRITE;
		}
		if(u){
			cur = &cur_fds[n];
			cur->events = ev;
			cur->fd = u;
			n++;
		}
	}

	return nfds;
}

#endif


static bool uloop_fd_stack_event(struct uloop_fd *fd, int events)
{
	struct uloop_fd_stack *cur;

	/*
	 * Do not buffer events for level-triggered fds, they will keep firing.
	 * Caller needs to take care of recursion issues.
	 */
	if (!(fd->flags & ULOOP_EDGE_TRIGGER))
		return false;

	for (cur = fd_stack; cur; cur = cur->next) {
		if (cur->fd != fd)
			continue;

		if (events < 0)
			cur->fd = NULL;
		else
			cur->events |= events | ULOOP_EVENT_BUFFERED;

		return true;
	}

	return false;
}

static void uloop_run_events(int timeout)
{
	struct uloop_fd_event *cur;
	struct uloop_fd *fd;

	if (!cur_nfds) {
		cur_fd = 0;
		cur_nfds = uloop_fetch_events(timeout);
		if (cur_nfds < 0)
			cur_nfds = 0;
	}

	while (cur_nfds > 0) {
		struct uloop_fd_stack stack_cur;
		unsigned int events;

		cur = &cur_fds[cur_fd++];
		cur_nfds--;

		fd = cur->fd;
		events = cur->events;
		if (!fd)
			continue;

		if (!fd->cb)
			continue;

		if (uloop_fd_stack_event(fd, cur->events))
			continue;

		stack_cur.next = fd_stack;
		stack_cur.fd = fd;
		fd_stack = &stack_cur;
		do {
			stack_cur.events = 0;
			fd->cb(fd, events);
			events = stack_cur.events & ULOOP_EVENT_MASK;
		} while (stack_cur.fd && events);
		fd_stack = stack_cur.next;

		return;
	}
}

int uloop_fd_add(struct uloop_fd *sock, unsigned int flags)
{
	unsigned int fl;
	int ret;

	if (!(flags & (ULOOP_READ | ULOOP_WRITE)))
		return uloop_fd_delete(sock);

#ifndef T_NONBLOCK
	if (!sock->registered && !(flags & ULOOP_BLOCKING)) {
		fl = fcntl(sock->fd, F_GETFL, 0);
		fl |= O_NONBLOCK;
		fcntl(sock->fd, F_SETFL, fl);
	}
#endif

	ret = register_poll(sock, flags);
	if (ret < 0)
		goto out;

	sock->registered = true;
	sock->eof = false;

out:
	return ret;
}

int uloop_fd_delete(struct uloop_fd *fd)
{
	int i;

	for (i = 0; i < cur_nfds; i++) {
		if (cur_fds[cur_fd + i].fd != fd)
			continue;

		cur_fds[cur_fd + i].fd = NULL;
	}

	if (!fd->registered)
		return 0;

	fd->registered = false;
	uloop_fd_stack_event(fd, -1);
	return __uloop_fd_delete(fd);
}

static int tv_diff(struct timeval *t1, struct timeval *t2)
{
	return
		(t1->tv_sec - t2->tv_sec) * 1000 +
		(t1->tv_usec - t2->tv_usec) / 1000;
}

int uloop_timeout_add(struct uloop_timeout *timeout)
{
	struct uloop_timeout *tmp;
	struct list_head *h = &timeouts;

	if (timeout->pending)
		return -1;

	list_for_each_entry(tmp, &timeouts, list) {
		if (tv_diff(&tmp->time, &timeout->time) > 0) {
			h = &tmp->list;
			break;
		}
	}

	list_add_tail(&timeout->list, h);
	timeout->pending = true;

	return 0;
}
#ifdef __ECOS
#define uloop_gettime(a) gettimeofday(a, NULL)
#else
static void uloop_gettime(struct timeval *tv)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}
#endif
int uloop_timeout_set(struct uloop_timeout *timeout, int msecs)
{
	struct timeval *time = &timeout->time;

	if (timeout->pending)
		uloop_timeout_cancel(timeout);

	uloop_gettime(&timeout->time);

	time->tv_sec += msecs / 1000;
	time->tv_usec += (msecs % 1000) * 1000;

	if (time->tv_usec > 1000000) {
		time->tv_sec++;
		time->tv_usec %= 1000000;
	}

	return uloop_timeout_add(timeout);
}

int uloop_timeout_cancel(struct uloop_timeout *timeout)
{
	if (!timeout->pending)
		return -1;

	list_del(&timeout->list);
	timeout->pending = false;

	return 0;
}

int uloop_timeout_remaining(struct uloop_timeout *timeout)
{
	struct timeval now;

	if (!timeout->pending)
		return -1;

	uloop_gettime(&now);

	return tv_diff(&timeout->time, &now);
}

#ifndef __ECOS

int uloop_process_add(struct uloop_process *p)
{
	struct uloop_process *tmp;
	struct list_head *h = &processes;

	D(BUS, "add process\n");

	if (p->pending)
		return -1;

	list_for_each_entry(tmp, &processes, list) {
		if (tmp->pid > p->pid) {
			h = &tmp->list;
			break;
		}
	}

	list_add_tail(&p->list, h);
	p->pending = true;

	return 0;
}

int uloop_process_delete(struct uloop_process *p)
{
	if (!p->pending)
		return -1;

	list_del(&p->list);
	p->pending = false;

	return 0;
}


static void uloop_handle_processes(void)
{
	struct uloop_process *p, *tmp;
	pid_t pid;
	int ret;

	do_sigchld = false;

	while (1) {
		pid = waitpid(-1, &ret, WNOHANG);
		if (pid <= 0)
			return;

		list_for_each_entry_safe(p, tmp, &processes, list) {
			if (p->pid < pid)
				continue;

			if (p->pid > pid)
				break;

			uloop_process_delete(p);
			p->cb(p, ret);
		}
	}

}


static void uloop_handle_sigint(int signo)
{
	uloop_cancelled = true;
}

static void uloop_sigchld(int signo)
{
	do_sigchld = true;
}

static void uloop_setup_signals(bool add)
{
	static struct sigaction old_sigint, old_sigchld;
	struct sigaction s;

	memset(&s, 0, sizeof(struct sigaction));

	if (add) {
		s.sa_handler = uloop_handle_sigint;
		s.sa_flags = 0;
	} else {
		s = old_sigint;
	}

	sigaction(SIGINT, &s, &old_sigint);

	if (!uloop_handle_sigchld)
		return;

	if (add)
		s.sa_handler = uloop_sigchld;
	else
		s = old_sigchld;

	sigaction(SIGCHLD, &s, &old_sigchld);
}

#endif

static int uloop_get_next_timeout(struct timeval *tv)
{
	struct uloop_timeout *timeout;
	int diff;

	if (list_empty(&timeouts))
		return -1;

	timeout = list_first_entry(&timeouts, struct uloop_timeout, list);
	diff = tv_diff(&timeout->time, tv);
	if (diff < 0)
		return 0;

	return diff;
}

static void uloop_process_timeouts(struct timeval *tv)
{
	struct uloop_timeout *t;

	while (!list_empty(&timeouts)) {
		t = list_first_entry(&timeouts, struct uloop_timeout, list);

		if (tv_diff(&t->time, tv) > 0)
			break;

		uloop_timeout_cancel(t);
		if (t->cb)
			t->cb(t);
	}
}

static void uloop_clear_timeouts(void)
{
	struct uloop_timeout *t, *tmp;

	list_for_each_entry_safe(t, tmp, &timeouts, list)
		uloop_timeout_cancel(t);
}
#ifndef __ECOS
static void uloop_clear_processes(void)
{
	struct uloop_process *p, *tmp;

	list_for_each_entry_safe(p, tmp, &processes, list)
		uloop_process_delete(p);
}
#endif

void uloop_run(void)
{
	static int recursive_calls = 0;
	struct timeval tv;

	/*
	 * Handlers are only updated for the first call to uloop_run() (and restored
	 * when this call is done).
	 */
#ifndef __ECOS
	if (!recursive_calls++)
		uloop_setup_signals(true);
#endif

	while(!uloop_cancelled)
	{
		uloop_gettime(&tv);
		uloop_process_timeouts(&tv);
		if (uloop_cancelled)
			break;

#ifndef __ECOS
		if (do_sigchld)
			uloop_handle_processes();
#endif
		uloop_gettime(&tv);
		uloop_run_events(uloop_get_next_timeout(&tv));
	}

#ifndef __ECOS
	if (!--recursive_calls)
		uloop_setup_signals(false);
#endif
}

void uloop_done(void)
{
	if (poll_fd < 0)
		return;
#ifndef USE_SELECT
	close(poll_fd);
#endif
	poll_fd = -1;

	uloop_clear_timeouts();
#ifndef __ECOS
	uloop_clear_processes();
#endif
}
