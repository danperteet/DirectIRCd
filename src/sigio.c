/*
 *  ircd-ratbox: A slightly useful ircd.
 *  sigio.c: Linux Realtime SIGIO compatible network routines.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
 *  Copyright (C) 2002 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2002 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: sigio.c 21361 2005-12-12 19:30:47Z androsyn $
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1		/* Needed for F_SETSIG */
#endif


#include "config.h"
#include "stdinc.h"
#include <signal.h>
#include <sys/poll.h>

#include "commio.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "irc_string.h"
#include "ircd.h"
#include "listener.h"
#include "numeric.h"
#include "packet.h"
#include "res.h"
#include "restart.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_log.h"
#include "s_serv.h"
#include "s_stats.h"
#include "send.h"
#include "memory.h"


/* I hate linux -- adrian */
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

struct _pollfd_list
{
	struct pollfd *pollfds;
	int maxindex;		/* highest FD number */
};

typedef struct _pollfd_list pollfd_list_t;

pollfd_list_t pollfd_list;
static void poll_update_pollfds(int, short, PF *);

static int sigio_signal;
static int sigio_is_screwed = 0;	/* We overflowed our sigio queue */
static sigset_t our_sigset;
static void poll_update_pollfds(int, short, PF *);

#define find_fd(x) (&fd_table[x])

/* 
 * static void mask_our_signal(int s)
 *
 * Input: Signal to block
 * Output: None
 * Side Effects:  Block the said signal
 */
static void
mask_our_signal(int s)
{
	sigemptyset(&our_sigset);
	sigaddset(&our_sigset, s);
	sigaddset(&our_sigset, SIGIO);
	sigprocmask(SIG_BLOCK, &our_sigset, NULL);
}

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Private functions */

/*
 * set and clear entries in the pollfds[] array.
 */

static void
poll_update_pollfds(int fd, short event, PF * handler)
{
	fde_t *F = &fd_table[fd];

	/* Update the events */
	if(handler)
	{
		F->list = FDLIST_IDLECLIENT;
		pollfd_list.pollfds[fd].events |= event;
		pollfd_list.pollfds[fd].fd = fd;
		/* update maxindex here */
		if(fd > pollfd_list.maxindex)
			pollfd_list.maxindex = fd;
	}
	else
	{
		pollfd_list.pollfds[fd].events &= ~event;
		if(pollfd_list.pollfds[fd].events == 0)
		{
			pollfd_list.pollfds[fd].fd = -1;
			pollfd_list.pollfds[fd].revents = 0;
			F->list = FDLIST_NONE;

			/* update pollfd_list.maxindex here */
			if(fd == pollfd_list.maxindex)
			{
				while (pollfd_list.maxindex >= 0 && pollfd_list.pollfds[pollfd_list.maxindex].fd == -1)
					pollfd_list.maxindex--;
			}
		}
	}
}


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Public functions */


/*
 * init_netio
 *
 * This is a needed exported function which will be called to initialise
 * the network loop code.
 */
void
init_netio(void)
{
	int fd;
	pollfd_list.pollfds = MyMalloc(maxconnections * sizeof(struct pollfd));
	for (fd = 0; fd < maxconnections; fd++)
	{
		pollfd_list.pollfds[fd].fd = -1;
	}
	pollfd_list.maxindex = 0;
        sigio_signal = SIGRTMIN;
	sigio_is_screwed = 1; /* Start off with poll first.. */
	mask_our_signal(sigio_signal);
}


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Public functions */


/*
 * void setup_sigio_fd(int fd)
 * 
 * Input: File descriptor
 * Output: None
 * Side Effect: Sets the FD up for SIGIO
 */
int
comm_setup_fd(int fd)
{
	fde_t *F = find_fd(fd);
	int flags = 0;
	flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1)
		return 0;
	flags |= O_ASYNC | O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) == -1)
		return 0;
	
	if(fcntl(fd, F_SETSIG, sigio_signal) == -1)
		return 0;

	if(fcntl(fd, F_SETOWN, getpid()) == -1)
		return 0;

	F->flags.nonblocking = 1;
	return 1;
}

/*
 * comm_setselect
 *
 * This is a needed exported function which will be called to register
 * and deregister interest in a pending IO state for a given FD.
 */
void
comm_setselect(int fd, fdlist_t list, unsigned int type, PF * handler,
	       void *client_data)
{
	fde_t *F = &fd_table[fd];
	s_assert(fd >= 0);
	s_assert(F->flags.open);

	if(type & COMM_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data = client_data;
		poll_update_pollfds(fd, POLLRDNORM, handler);
	}
	if(type & COMM_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data = client_data;
		poll_update_pollfds(fd, POLLWRNORM, handler);
	}
}

/* int comm_select(unsigned long delay)
 * Input: The maximum time to delay.
 * Output: Returns -1 on error, 0 on success.
 * Side-effects: Deregisters future interest in IO and calls the handlers
 *               if an event occurs for an FD.
 * Comments: Check all connections for new connections and input data
 * that is to be processed. Also check for connections with data queued
 * and whether we can write it out.
 * Called to do the new-style IO, courtesy of squid (like most of this
 * new IO code). This routine handles the stuff we've hidden in
 * comm_setselect and fd_table[] and calls callbacks for IO ready
 * events.
 */
int
comm_select(unsigned long delay)
{
	int num = 0;
	int revents = 0;
	int sig;
	int fd;
	int ci;
	PF *hdl;
	fde_t *F;
	void *data;
	struct siginfo si;
	struct timespec timeout;

	timeout.tv_sec = (delay / 1000);
	timeout.tv_nsec = (delay % 1000) * 1000000;

	for (;;)
	{
		if(!sigio_is_screwed)
		{
			if((sig = sigtimedwait(&our_sigset, &si, &timeout)) > 0)
			{
				if(sig == SIGIO)
				{
					ilog(L_IOERROR, "Kernel RT Signal queue overflowed.  Is /proc/sys/kernel/rtsig-max too small?");
					sigio_is_screwed = 1;
					break;
				}

				fd = si.si_fd;
				pollfd_list.pollfds[fd].revents |= si.si_band;
				revents = pollfd_list.pollfds[fd].revents;
				num++;
				F = &fd_table[fd];
				if(!F->flags.open || F->fd < 0)
					continue;

				set_time();
				if(revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
				{
					hdl = F->read_handler;
					data = F->read_data;
					F->read_handler = NULL;
					F->read_data = NULL;
					poll_update_pollfds(fd, POLLIN, NULL);
					if(hdl)
						hdl(F->fd, data);
				}

				if(revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR))
				{
					hdl = F->write_handler;
					data = F->write_data;
					F->write_handler = NULL;
					F->write_data = NULL;
					poll_update_pollfds(fd, POLLOUT, NULL);
					if(hdl)
						hdl(F->fd, data);
				}
			}
			else
				break;

		}
		else
			break;
	}

	if(!sigio_is_screwed)	/* We don't need to proceed */
	{
		set_time();
		return 0;
	}

	signal(sigio_signal, SIG_IGN);
	signal(sigio_signal, SIG_DFL);
	sigio_is_screwed = 0;

	for (;;)
	{
		/* XXX kill that +1 later ! -- adrian */
		num = poll(pollfd_list.pollfds, pollfd_list.maxindex + 1, delay);
		if(num >= 0)
			break;
		if(ignoreErrno(errno))
			continue;
		/* error! */
		set_time();
		return -1;
		/* NOTREACHED */
	}

	/* update current time again, eww.. */
	set_time();

	if(num == 0)
		return 0;
	/* XXX we *could* optimise by falling out after doing num fds ... */
	for (ci = 0; ci < pollfd_list.maxindex + 1; ci++)
	{
		fde_t *F;
		int revents;
		if(((revents = pollfd_list.pollfds[ci].revents) == 0) ||
		   (pollfd_list.pollfds[ci].fd) == -1)
			continue;
		fd = pollfd_list.pollfds[ci].fd;
		F = &fd_table[fd];
		if(revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
		{
			hdl = F->read_handler;
			F->read_handler = NULL;
			poll_update_pollfds(fd, POLLRDNORM, NULL);
			if(hdl)
				hdl(fd, F->read_data);
		}
		if(revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR))
		{
			hdl = F->write_handler;
			F->write_handler = NULL;
			poll_update_pollfds(fd, POLLWRNORM, NULL);
			if(hdl)
				hdl(fd, F->write_data);
		}
	}
	return 0;
}

