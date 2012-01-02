/*
 *  ircd-ratbox: A slightly useful ircd.
 *  send.c: Functions for sending messages.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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
 *  $Id: send.c 23975 2007-06-30 22:34:38Z jilles $
 */

#include "stdinc.h"
#include "tools.h"
#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "irc_string.h"
#include "ircd.h"
#include "numeric.h"
#include "commio.h"
#include "s_serv.h"
#include "sprintf_irc.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "linebuf.h"
#include "s_log.h"
#include "memory.h"
#include "hook.h"
#include "monitor.h"

/* send the message to the link the target is attached to */
#define send_linebuf(a,b) _send_linebuf((a->from ? a->from : a) ,b)

unsigned long current_serial = 0L;

/* send_linebuf()
 *
 * inputs	- client to send to, linebuf to attach
 * outputs	-
 * side effects - linebuf is attached to client
 */
static int
_send_linebuf(struct Client *to, buf_head_t *linebuf)
{
	if(IsMe(to))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send message to myself!");
		return 0;
	}

	if(!MyConnect(to) || IsIOError(to))
		return 0;

	if(linebuf_len(&to->localClient->buf_sendq) > get_sendq(to))
	{
		if(IsServer(to))
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Max SendQ limit exceeded for %s: %u > %lu",
					     to->name,
					     linebuf_len(&to->localClient->buf_sendq), 
					     get_sendq(to));

			ilog(L_SERVER, "Max SendQ limit exceeded for %s: %u > %lu",
			     log_client_name(to, SHOW_IP),
			     linebuf_len(&to->localClient->buf_sendq), 
			     get_sendq(to));
		}

		dead_link(to, 1);
		return -1;
	}
	else
	{
		/* just attach the linebuf to the sendq instead of
		 * generating a new one
		 */
		linebuf_attach(&to->localClient->buf_sendq, linebuf);
	}

	/*
	 ** Update statistics. The following is slightly incorrect
	 ** because it counts messages even if queued, but bytes
	 ** only really sent. Queued bytes get updated in SendQueued.
	 */
	to->localClient->sendM += 1;
	me.localClient->sendM += 1;
	if(linebuf_len(&to->localClient->buf_sendq) > 0)
		send_queued_write(to->localClient->fd, to);
	return 0;
}

/* send_linebuf_remote()
 *
 * inputs	- client to attach to, sender, linebuf
 * outputs	-
 * side effects - client has linebuf attached
 */
static void
send_linebuf_remote(struct Client *to, struct Client *from, buf_head_t *linebuf)
{
	if(to->from)
		to = to->from;

	/* test for fake direction */
	if(!MyClient(from) && IsPerson(to) && (to == from->from))
	{
		if(IsServer(from))
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Send message to %s[%s] dropped from %s(Fake Dir)",
					     to->name, to->from->name, from->name);
			return;
		}

		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Ghosted: %s[%s@%s] from %s[%s@%s] (%s)",
				     to->name, to->username, to->host,
				     from->name, from->username, from->host, to->from->name);
		kill_client_serv_butone(NULL, to, "%s (%s[%s@%s] Ghosted %s)",
					me.name, to->name, to->username,
					to->host, to->from->name);

		to->flags |= FLAGS_KILLED;

		exit_client(NULL, to, &me, "Ghosted client");
		return;
	}

	_send_linebuf(to, linebuf);
	return;
}

/* send_queued_write()
 *
 * inputs	- fd to have queue sent, client we're sending to
 * outputs	- contents of queue
 * side effects - write is rescheduled if queue isnt emptied
 */
void
send_queued_write(int fd, void *data)
{
	struct Client *to = data;
	int retlen;
	int flags;
#ifdef USE_IODEBUG_HOOKS
	hook_data_int hd;
#endif
	/* cant write anything to a dead socket. */
	if(IsIOError(to))
		return;

#ifdef USE_IODEBUG_HOOKS
	hd.client = to;
	if(to->localClient->buf_sendq.list.head)
		hd.arg1 = ((buf_line_t *) to->localClient->buf_sendq.list.head->data)->buf +
	                     to->localClient->buf_sendq.writeofs;
#endif

	if(linebuf_len(&to->localClient->buf_sendq))
	{
		while ((retlen =
			linebuf_flush(to->localClient->fd, &to->localClient->buf_sendq)) > 0)
		{
			/* We have some data written .. update counters */
#ifdef USE_IODEBUG_HOOKS
                        hd.arg2 = retlen;
                        call_hook(h_iosend_id, &hd);

                        if(to->localClient->buf_sendq.list.head)
                                hd.arg1 =
                                        ((buf_line_t *) to->localClient->buf_sendq.list.head->
                                         data)->buf + to->localClient->buf_sendq.writeofs;
#endif
     

			to->localClient->sendB += retlen;
			me.localClient->sendB += retlen;
			if(to->localClient->sendB > 1023)
			{
				to->localClient->sendK += (to->localClient->sendB >> 10);
				to->localClient->sendB &= 0x03ff;	/* 2^10 = 1024, 3ff = 1023 */
			}
			else if(me.localClient->sendB > 1023)
			{
				me.localClient->sendK += (me.localClient->sendB >> 10);
				me.localClient->sendB &= 0x03ff;
			}
		}

		if(retlen == 0 || (retlen < 0 && !ignoreErrno(errno)))
		{
			dead_link(to, 0);
			return;
		}
	}
	if(ignoreErrno(errno))
		flags = COMM_SELECT_WRITE|COMM_SELECT_RETRY;
	else
		flags = COMM_SELECT_WRITE;
	if(linebuf_len(&to->localClient->buf_sendq))
	comm_setselect(fd, FDLIST_IDLECLIENT, flags,
			       send_queued_write, to);
}

/* send_queued_slink_write()
 *
 * inputs	- fd to have queue sent, client we're sending to
 * outputs	- contents of queue
 * side effects - write is rescheduled if queue isnt emptied
 */
void
send_queued_slink_write(int fd, void *data)
{
	struct Client *to = data;
	int retlen;

	/*
	 ** Once socket is marked dead, we cannot start writing to it,
	 ** even if the error is removed...
	 */
	if(IsIOError(to))
		return;

	/* Next, lets try to write some data */
	if(to->localClient->slink->slinkq)
	{
		retlen = write(to->localClient->slink->ctrlfd,
			      to->localClient->slink->slinkq + to->localClient->slink->slinkq_ofs,
			      to->localClient->slink->slinkq_len);

		if(retlen < 0)
		{
			/* If we have a fatal error */
			if(!ignoreErrno(errno))
			{
				dead_link(to, 0);
				return;
			}
		}
		/* 0 bytes is an EOF .. */
		else if(retlen == 0)
		{
			dead_link(to, 0);
			return;
		}
		else
		{
			to->localClient->slink->slinkq_len -= retlen;

			s_assert(to->localClient->slink->slinkq_len >= 0);
			if(to->localClient->slink->slinkq_len)
				to->localClient->slink->slinkq_ofs += retlen;
			else
			{
				to->localClient->slink->slinkq_ofs = 0;
				MyFree(to->localClient->slink->slinkq);
				to->localClient->slink->slinkq = NULL;
			}
		}
	}

	/* if we have any more data, reschedule a write */
	if(to->localClient->slink->slinkq_len)
		comm_setselect(to->localClient->slink->ctrlfd, 
				FDLIST_IDLECLIENT,
				COMM_SELECT_WRITE|COMM_SELECT_RETRY, 
				send_queued_slink_write, to);
}

/* sendto_one()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - 
 */
void
sendto_one(struct Client *target_p, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		target_p = target_p->from;

	if(IsIOError(target_p))
		return;

	linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	_send_linebuf(target_p, &linebuf);

	linebuf_donebuf(&linebuf);

}

/* sendto_one_prefix()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - source(us)/target is chosen based on TS6 capability
 */
void
sendto_one_prefix(struct Client *target_p, struct Client *source_p,
		  const char *command, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		dest_p = target_p->from;
	else
		dest_p = target_p;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args,
		       ":%s %s %s ",
		       get_id(source_p, target_p),
		       command, get_id(target_p, target_p));
	va_end(args);

	_send_linebuf(dest_p, &linebuf);
	linebuf_donebuf(&linebuf);
}

/* sendto_one_notice()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has a NOTICE put into its queue
 * side effects - source(us)/target is chosen based on TS6 capability
 */
void
sendto_one_notice(struct Client *target_p, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		dest_p = target_p->from;
	else
		dest_p = target_p;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args,
		       ":%s NOTICE %s ",
		       get_id(&me, target_p), get_id(target_p, target_p));
	va_end(args);

	_send_linebuf(dest_p, &linebuf);
	linebuf_donebuf(&linebuf);
}


/* sendto_one_numeric()
 *
 * inputs	- client to send to, va_args
 * outputs	- client has message put into its queue
 * side effects - source/target is chosen based on TS6 capability
 */
void
sendto_one_numeric(struct Client *target_p, int numeric, const char *pattern, ...)
{
	struct Client *dest_p;
	va_list args;
	buf_head_t linebuf;

	/* send remote if to->from non NULL */
	if(target_p->from != NULL)
		dest_p = target_p->from;
	else
		dest_p = target_p;

	if(IsIOError(dest_p))
		return;

	if(IsMe(dest_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Trying to send to myself!");
		return;
	}

	linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args,
		       ":%s %03d %s ",
		       get_id(&me, target_p),
		       numeric, get_id(target_p, target_p));
	va_end(args);

	_send_linebuf(dest_p, &linebuf);
	linebuf_donebuf(&linebuf);
}

/*
 * sendto_server
 * 
 * inputs       - pointer to client to NOT send to
 *              - caps or'd together which must ALL be present
 *              - caps or'd together which must ALL NOT be present
 *              - printf style format string
 *              - args to format string
 * output       - NONE
 * side effects - Send a message to all connected servers, except the
 *                client 'one' (if non-NULL), as long as the servers
 *                support ALL capabs in 'caps', and NO capabs in 'nocaps'.
 *            
 * This function was written in an attempt to merge together the other
 * billion sendto_*serv*() functions, which sprung up with capabs, uids etc
 * -davidt
 */
void
sendto_server(struct Client *one, struct Channel *chptr, unsigned long caps,
	      unsigned long nocaps, const char *format, ...)
{
	va_list args;
	struct Client *target_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	buf_head_t linebuf;

	/* noone to send to.. */
	if(dlink_list_length(&serv_list) == 0)
		return;

	if(chptr != NULL && *chptr->chname != '#')
			return;

	linebuf_newbuf(&linebuf);
	va_start(args, format);
	linebuf_putmsg(&linebuf, format, &args, NULL);
	va_end(args);

	DLINK_FOREACH_SAFE(ptr, next_ptr, serv_list.head)
	{
		target_p = ptr->data;

		/* check against 'one' */
		if(one != NULL && (target_p == one->from))
			continue;

		/* check we have required capabs */
		if(!IsCapable(target_p, caps))
			continue;

		/* check we don't have any forbidden capabs */
		if(!NotCapable(target_p, nocaps))
			continue;

		_send_linebuf(target_p, &linebuf);
	}

	linebuf_donebuf(&linebuf);

}

/* sendto_channel_flags()
 *
 * inputs	- server not to send to, flags needed, source, channel, va_args
 * outputs	- message is sent to channel members
 * side effects -
 */
void
sendto_channel_flags(struct Client *one, int type, struct Client *source_p,
		     struct Channel *chptr, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	buf_head_t linebuf_local;
	buf_head_t linebuf_name;
	buf_head_t linebuf_id;
	struct Client *target_p;
	struct membership *msptr;
	dlink_node *ptr;
	dlink_node *next_ptr;

	linebuf_newbuf(&linebuf_local);
	linebuf_newbuf(&linebuf_name);
	linebuf_newbuf(&linebuf_id);

	current_serial++;

	va_start(args, pattern);
	ircvsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	if(IsServer(source_p))
		linebuf_putmsg(&linebuf_local, NULL, NULL,
			       ":%s %s", source_p->name, buf);
	else
		linebuf_putmsg(&linebuf_local, NULL, NULL,
			       ":%s!%s@%s %s",
			       source_p->name, source_p->username, 
			       source_p->host, buf);

	linebuf_putmsg(&linebuf_name, NULL, NULL, ":%s %s", source_p->name, buf);
	linebuf_putmsg(&linebuf_id, NULL, NULL, ":%s %s", use_id(source_p), buf);

	DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->members.head)
	{
		msptr = ptr->data;
		target_p = msptr->client_p;

		if(IsIOError(target_p->from) || target_p->from == one)
			continue;

		if(type && ((msptr->flags & type) == 0))
			continue;

		if(IsDeaf(target_p))
			continue;

		if(!MyClient(target_p))
		{
			/* if we've got a specific type, target must support
			 * CHW.. --fl
			 */
			if(type && NotCapable(target_p->from, CAP_CHW))
				continue;

			if(target_p->from->localClient->serial != current_serial)
			{
				if(has_id(target_p->from))
					send_linebuf_remote(target_p, source_p, &linebuf_id);
				else
					send_linebuf_remote(target_p, source_p, &linebuf_name);

				target_p->from->localClient->serial = current_serial;
			}
		}
		else
			_send_linebuf(target_p, &linebuf_local);
	}

	linebuf_donebuf(&linebuf_local);
	linebuf_donebuf(&linebuf_name);
	linebuf_donebuf(&linebuf_id);
}


/* sendto_channel_local()
 *
 * inputs	- flags to send to, channel to send to, va_args
 * outputs	- message to local channel members
 * side effects -
 */
void
sendto_channel_local(int type, struct Channel *chptr, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;
	struct membership *msptr;
	struct Client *target_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	
	linebuf_newbuf(&linebuf); 
	
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->locmembers.head)
	{
		msptr = ptr->data;
		target_p = msptr->client_p;

		if(IsIOError(target_p))
			continue;

		if(type && ((msptr->flags & type) == 0))
			continue;

		_send_linebuf(target_p, &linebuf);
	}

	linebuf_donebuf(&linebuf);
}

/*
 * sendto_common_channels_local()
 *
 * inputs	- pointer to client
 *		- pattern to send
 * output	- NONE
 * side effects	- Sends a message to all people on local server who are
 * 		  in same channel with user. 
 *		  used by m_nick.c and exit_one_client.
 */
void
sendto_common_channels_local(struct Client *user, const char *pattern, ...)
{
	va_list args;
	dlink_node *ptr;
	dlink_node *next_ptr;
	dlink_node *uptr;
	dlink_node *next_uptr;
	struct Channel *chptr;
	struct Client *target_p;
	struct membership *msptr;
	struct membership *mscptr;
	buf_head_t linebuf;

	linebuf_newbuf(&linebuf);
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	++current_serial;

	DLINK_FOREACH_SAFE(ptr, next_ptr, user->user->channel.head)
	{
		mscptr = ptr->data;
		chptr = mscptr->chptr;

		DLINK_FOREACH_SAFE(uptr, next_uptr, chptr->locmembers.head)
		{
			msptr = uptr->data;
			target_p = msptr->client_p;

			if(IsIOError(target_p) ||
			   target_p->localClient->serial == current_serial)
				continue;

			target_p->localClient->serial = current_serial;
			send_linebuf(target_p, &linebuf);
		}
	}

	/* this can happen when the user isnt in any channels, but we still
	 * need to send them the data, ie a nick change
	 */
	if(MyConnect(user) && (user->localClient->serial != current_serial))
		send_linebuf(user, &linebuf);

	linebuf_donebuf(&linebuf);
}

/* sendto_match_butone()
 *
 * inputs	- server not to send to, source, mask, type of mask, va_args
 * output	-
 * side effects - message is sent to matching clients
 */
void
sendto_match_butone(struct Client *one, struct Client *source_p,
		    const char *mask, int what, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	struct Client *target_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	buf_head_t linebuf_local;
	buf_head_t linebuf_name;
	buf_head_t linebuf_id;

	linebuf_newbuf(&linebuf_local);
	linebuf_newbuf(&linebuf_name);
	linebuf_newbuf(&linebuf_id);

	va_start(args, pattern);
	ircvsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	if(IsServer(source_p))
		linebuf_putmsg(&linebuf_local, NULL, NULL,
			       ":%s %s", source_p->name, buf);
	else
		linebuf_putmsg(&linebuf_local, NULL, NULL,
			       ":%s!%s@%s %s",
			       source_p->name, source_p->username, 
			       source_p->host, buf);

	linebuf_putmsg(&linebuf_name, NULL, NULL, ":%s %s", source_p->name, buf);
	linebuf_putmsg(&linebuf_id, NULL, NULL, ":%s %s", use_id(source_p), buf);

	if(what == MATCH_HOST)
	{
		DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
		{
			target_p = ptr->data;

			if(match(mask, target_p->host))
				_send_linebuf(target_p, &linebuf_local);
		}
	}
	/* what = MATCH_SERVER, if it doesnt match us, just send remote */
	else if(match(mask, me.name))
	{
		DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
		{
			target_p = ptr->data;
			_send_linebuf(target_p, &linebuf_local);
		}
	}

	DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if(target_p == one)
			continue;

		if(has_id(target_p))
			send_linebuf_remote(target_p, source_p, &linebuf_id);
		else
			send_linebuf_remote(target_p, source_p, &linebuf_name);
	}

	linebuf_donebuf(&linebuf_local);
	linebuf_donebuf(&linebuf_id);
	linebuf_donebuf(&linebuf_name);
}

/* sendto_match_servs()
 *
 * inputs       - source, mask to send to, caps needed, va_args
 * outputs      - 
 * side effects - message is sent to matching servers with caps.
 */
void
sendto_match_servs(struct Client *source_p, const char *mask, int cap, 
			int nocap, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	dlink_node *ptr;
	struct Client *target_p;
	buf_head_t linebuf_id;
	buf_head_t linebuf_name;

	if(EmptyString(mask))
		return;

	linebuf_newbuf(&linebuf_id);
	linebuf_newbuf(&linebuf_name);

	va_start(args, pattern);
	ircvsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	linebuf_putmsg(&linebuf_id, NULL, NULL, 
			":%s %s", use_id(source_p), buf);
	linebuf_putmsg(&linebuf_name, NULL, NULL, 
			":%s %s", source_p->name, buf);

	current_serial++;

	DLINK_FOREACH(ptr, global_serv_list.head)
	{
		target_p = ptr->data;

		/* dont send to ourselves, or back to where it came from.. */
		if(IsMe(target_p) || target_p->from == source_p->from)
			continue;

		if(target_p->from->localClient->serial == current_serial)
			continue;

		if(match(mask, target_p->name))
		{
			/* if we set the serial here, then we'll never do
			 * a match() again if !IsCapable()
			 */
			target_p->from->localClient->serial = current_serial;

			if(cap && !IsCapable(target_p->from, cap))
				continue;

			if(nocap && !NotCapable(target_p->from, nocap))
				continue;

			if(has_id(target_p->from))
				_send_linebuf(target_p->from, &linebuf_id);
			else
				_send_linebuf(target_p->from, &linebuf_name);
		}
	}

	linebuf_donebuf(&linebuf_id);
	linebuf_donebuf(&linebuf_name);
}

/* sendto_monitor()
 *
 * inputs	- monitor nick to send to, format, va_args
 * outputs	- message to local users monitoring the given nick
 * side effects -
 */
void
sendto_monitor(struct monitor *monptr, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;
	struct Client *target_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	
	linebuf_newbuf(&linebuf); 
	
	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, NULL);
	va_end(args);

	DLINK_FOREACH_SAFE(ptr, next_ptr, monptr->users.head)
	{
		target_p = ptr->data;

		if(IsIOError(target_p))
			continue;

		_send_linebuf(target_p, &linebuf);
	}

	linebuf_donebuf(&linebuf);
}

/* sendto_anywhere()
 *
 * inputs	- target, source, va_args
 * outputs	-
 * side effects - client is sent message with correct prefix.
 */
void
sendto_anywhere(struct Client *target_p, struct Client *source_p, 
		const char *command, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	linebuf_newbuf(&linebuf);

	va_start(args, pattern);

	if(MyClient(target_p))
	{
		if(IsServer(source_p))
			linebuf_putmsg(&linebuf, pattern, &args, ":%s %s %s ",
				       source_p->name, command, 
				       target_p->name);
		else
			linebuf_putmsg(&linebuf, pattern, &args, 
				       ":%s!%s@%s %s %s ", 
				       source_p->name, source_p->username,
				       source_p->host, command,
				       target_p->name);
	}
	else
		linebuf_putmsg(&linebuf, pattern, &args, ":%s %s %s ",
			       get_id(source_p, target_p), command,
			       get_id(target_p, target_p));
	va_end(args);

	if(MyClient(target_p))
		_send_linebuf(target_p, &linebuf);
	else
		send_linebuf_remote(target_p, source_p, &linebuf);

	linebuf_donebuf(&linebuf);
}

/* sendto_realops_flags()
 *
 * inputs	- umode needed, level (opers/admin), va_args
 * output	-
 * side effects - message is sent to opers with matching umodes
 */
void
sendto_realops_flags(int flags, int level, const char *pattern, ...)
{
	struct Client *client_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	va_list args;
	buf_head_t linebuf;

	linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, 
		       ":%s NOTICE * :*** Notice -- ", me.name);
	va_end(args);

	DLINK_FOREACH_SAFE(ptr, next_ptr, oper_list.head)
	{
		client_p = ptr->data;

		/* If we're sending it to opers and theyre an admin, skip.
		 * If we're sending it to admins, and theyre not, skip.
		 */
		if(((level == L_ADMIN) && !IsAdmin(client_p)) ||
		   ((level == L_OPER) && IsAdmin(client_p)))
			continue;

		if(client_p->umodes & flags)
			_send_linebuf(client_p, &linebuf);
	}

	linebuf_donebuf(&linebuf);
}

/*
 * sendto_wallops_flags
 *
 * inputs       - flag types of messages to show to real opers
 *              - client sending request
 *              - var args input message
 * output       - NONE
 * side effects - Send a wallops to local opers
 */
void
sendto_wallops_flags(int flags, struct Client *source_p, const char *pattern, ...)
{
	struct Client *client_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	va_list args;
	buf_head_t linebuf;

	linebuf_newbuf(&linebuf);

	va_start(args, pattern);

	if(IsPerson(source_p))
		linebuf_putmsg(&linebuf, pattern, &args,
			       ":%s!%s@%s WALLOPS :", source_p->name,
			       source_p->username, source_p->host);
	else
		linebuf_putmsg(&linebuf, pattern, &args, ":%s WALLOPS :", source_p->name);

	va_end(args);

	DLINK_FOREACH_SAFE(ptr, next_ptr, oper_list.head)
	{
		client_p = ptr->data;

		/* dont allow people without operwall privs to see operwalls */
		if((flags == UMODE_OPERWALL) && !IsOperOperwall(client_p))
			continue;

		if(client_p->umodes & flags)
			_send_linebuf(client_p, &linebuf);
	}

	linebuf_donebuf(&linebuf);
}

/* kill_client()
 *
 * input	- client to send kill to, client to kill, va_args
 * output	-
 * side effects - we issue a kill for the client
 */
void
kill_client(struct Client *target_p, struct Client *diedie, const char *pattern, ...)
{
	va_list args;
	buf_head_t linebuf;

	linebuf_newbuf(&linebuf);

	va_start(args, pattern);
	linebuf_putmsg(&linebuf, pattern, &args, ":%s KILL %s :",
		      get_id(&me, target_p), get_id(diedie, target_p));
	va_end(args);

	send_linebuf(target_p, &linebuf);
	linebuf_donebuf(&linebuf);
}


/*
 * kill_client_serv_butone
 *
 * inputs	- pointer to client to not send to
 *		- pointer to client to kill
 * output	- NONE
 * side effects	- Send a KILL for the given client
 *		  message to all connected servers
 *                except the client 'one'. Also deal with
 *		  client being unknown to leaf, as in lazylink...
 */
void
kill_client_serv_butone(struct Client *one, struct Client *target_p, const char *pattern, ...)
{
	static char buf[BUFSIZE];
	va_list args;
	struct Client *client_p;
	dlink_node *ptr;
	dlink_node *next_ptr;
	buf_head_t linebuf_id;
	buf_head_t linebuf_name;

	linebuf_newbuf(&linebuf_name);
	linebuf_newbuf(&linebuf_id);
	
	va_start(args, pattern);
	ircvsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);

	linebuf_putmsg(&linebuf_name, NULL, NULL, ":%s KILL %s :%s",
		       me.name, target_p->name, buf);
	linebuf_putmsg(&linebuf_id, NULL, NULL, ":%s KILL %s :%s",
		       use_id(&me), use_id(target_p), buf);

	DLINK_FOREACH_SAFE(ptr, next_ptr, serv_list.head)
	{
		client_p = ptr->data;

		/* ok, if the client we're supposed to not send to has an
		 * ID, then we still want to issue the kill there..
		 */
		if(one != NULL && (client_p == one->from) &&
			(!has_id(client_p) || !has_id(target_p)))
			continue;

		if(has_id(client_p))
			_send_linebuf(client_p, &linebuf_id);
		else
			_send_linebuf(client_p, &linebuf_name);
	}

	linebuf_donebuf(&linebuf_id);
	linebuf_donebuf(&linebuf_name);
}
