/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_sjoin.c: Joins a user to a channel.
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
 *  $Id: m_sjoin.c 22848 2006-07-05 13:35:49Z jilles $
 */

#include "stdinc.h"
#include "tools.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "common.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_serv.h"
#include "s_conf.h"

static int ms_sjoin(struct Client *, struct Client *, int, const char **);

struct Message sjoin_msgtab = {
	"SJOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_ignore, mg_ignore, {ms_sjoin, 0}, mg_ignore, mg_ignore}
};

mapi_clist_av1 sjoin_clist[] = { &sjoin_msgtab, NULL };
DECLARE_MODULE_AV1(sjoin, NULL, NULL, sjoin_clist, NULL, NULL, "$Revision: 22848 $");

/*
 * ms_sjoin
 * parv[0] - sender
 * parv[1] - TS
 * parv[2] - channel
 * parv[3] - modes + n arguments (key and/or limit)
 * parv[4+n] - flags+nick list (all in one parameter)
 * 
 * process a SJOIN, taking the TS's into account to either ignore the
 * incoming modes or undo the existing ones or merge them, and JOIN
 * all the specified users while sending JOIN/MODEs to local clients
 */


static char modebuf[MODEBUFLEN];
static char parabuf[MODEBUFLEN];
static const char *para[MAXMODEPARAMS];
static char *mbuf;
static int pargs;

static void set_final_mode(struct Mode *mode, struct Mode *oldmode);
static void remove_our_modes(struct Channel *chptr, struct Client *source_p);
static void remove_ban_list(struct Channel *chptr, struct Client *source_p,
			    dlink_list *list, char c, int cap, int mems);

static int
ms_sjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static char buf_nick[BUFSIZE];
	static char buf_uid[BUFSIZE];
	static const char empty_modes[] = "0";
	struct Channel *chptr;
	struct Client *target_p;
	time_t newts;
	time_t oldts;
	static struct Mode mode, *oldmode;
	const char *modes;
	int args = 0;
	int keep_our_modes = 1;
	int keep_new_modes = 1;
	int fl;
	int isnew;
	int mlen_nick, mlen_uid;
	int len_nick;
	int len_uid;
	int len;
	int joins = 0;
	const char *s;
	char *ptr_nick;
	char *ptr_uid;
	char *p;
	int i;
	static char empty[] = "";

	/* I dont trust servers *not* to end up sending us a blank sjoin, so
	 * its better not to make a big deal about it. --fl
	 */
	if(parc < 5 || EmptyString(parv[4]))
		return 0;

	if(!IsChannelName(parv[2]) || !check_channel_name(parv[2]))
		return 0;

	/* SJOIN's for local channels can't happen. */
	if(*parv[2] == '&')
		return 0;

	modebuf[0] = parabuf[0] = mode.key[0] = '\0';
	pargs = mode.mode = mode.limit = 0;

	mbuf = modebuf;
	newts = atol(parv[1]);

	s = parv[3];
	while (*s)
	{
		switch (*(s++))
		{
		case 'i':
			mode.mode |= MODE_INVITEONLY;
			break;
		case 'n':
			mode.mode |= MODE_NOPRIVMSGS;
			break;
		case 'p':
			mode.mode |= MODE_PRIVATE;
			break;
		case 's':
			mode.mode |= MODE_SECRET;
			break;
		case 'm':
			mode.mode |= MODE_MODERATED;
			break;
		case 't':
			mode.mode |= MODE_TOPICLIMIT;
			break;
#ifdef ENABLE_SERVICES
		case 'r':
			mode.mode |= MODE_REGONLY;
			break;
#endif
		case 'k':
			strlcpy(mode.key, parv[4 + args], sizeof(mode.key));
			args++;
			if(parc < 5 + args)
				return 0;
			break;
		case 'l':
			mode.limit = atoi(parv[4 + args]);
			args++;
			if(parc < 5 + args)
				return 0;
			break;
		}
	}

	s = parv[args + 4];

	/* remove any leading spaces */
	while (*s == ' ')
		s++;

	if(EmptyString(s))
		return 0;

	if((chptr = get_or_create_channel(source_p, parv[2], &isnew)) == NULL)
		return 0;		/* channel name too long? */


	oldts = chptr->channelts;
	oldmode = &chptr->mode;

	if(!isnew && !newts && oldts)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s "
                                     "changed from %ld to 0",
				     me.name, chptr->chname, chptr->chname, (long) oldts);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Server %s changing TS on %s from %ld to 0",
				     source_p->name, chptr->chname, (long) oldts);
	}

	if(isnew)
		chptr->channelts = newts;
	else if(newts == 0 || oldts == 0)
		chptr->channelts = 0;
	else if(newts == oldts)
		;
	else if(newts < oldts)
	{
		keep_our_modes = NO;
		chptr->channelts = newts;
	}
	else
		keep_new_modes = NO;

	if(!keep_new_modes)
		mode = *oldmode;
	else if(keep_our_modes)
	{
		mode.mode |= oldmode->mode;
		if(oldmode->limit > mode.limit)
			mode.limit = oldmode->limit;
		if(strcmp(mode.key, oldmode->key) < 0)
			strcpy(mode.key, oldmode->key);
	}

	set_final_mode(&mode, oldmode);
	chptr->mode = mode;

	/* Lost the TS, other side wins, so remove modes on this side */
	if(!keep_our_modes)
	{
		remove_our_modes(chptr, source_p);
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to %ld",
				     me.name, chptr->chname, chptr->chname,
				     (long) oldts, (long) newts);
	}

	if(*modebuf != '\0')
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s %s %s",
				     source_p->name, chptr->chname, 
				     modebuf, parabuf);

	*modebuf = *parabuf = '\0';

	if(parv[3][0] != '0' && keep_new_modes)
		modes = channel_modes(chptr, source_p);
	else
		modes = empty_modes;

	mlen_nick = ircsprintf(buf_nick, ":%s SJOIN %ld %s %s :",
			  source_p->name, (long) chptr->channelts,
			  parv[2], modes);
	ptr_nick = buf_nick + mlen_nick;

	/* working on the presumption eventually itll be more efficient to
	 * build a TS6 buffer without checking its needed..
	 */
	mlen_uid = ircsprintf(buf_uid, ":%s SJOIN %ld %s %s :",
			  use_id(source_p), (long) chptr->channelts,
			  parv[2], modes);
	ptr_uid = buf_uid + mlen_uid;

	mbuf = modebuf;
	para[0] = para[1] = para[2] = para[3] = empty;
	pargs = 0;
	len_nick = len_uid = 0;

	*mbuf++ = '+';

	/* if theres a space, theres going to be more than one nick, change the
	 * first space to \0, so s is just the first nick, and point p to the
	 * second nick
	 */
	if((p = strchr(s, ' ')) != NULL)
	{
		*p++ = '\0';
	}

	while (s)
	{
		fl = 0;

		for (i = 0; i < 2; i++)
		{
			if(*s == '@')
			{
				fl |= CHFL_CHANOP;
				s++;
			}
			else if(*s == '+')
			{
				fl |= CHFL_VOICE;
				s++;
			}
		}

		/* if the client doesnt exist or is fake direction, skip. */
		if(!(target_p = find_client(s)) ||
		   (target_p->from != client_p) || !IsPerson(target_p))
			goto nextnick;

		/* we assume for these we can fit at least one nick/uid in.. */

		/* check we can fit another status+nick+space into a buffer */
		if((mlen_nick + len_nick + NICKLEN + 3) > (BUFSIZE - 3))
		{
			*(ptr_nick - 1) = '\0';
			sendto_server(client_p->from, NULL, NOCAPS, CAP_TS6,
				      "%s", buf_nick);
			ptr_nick = buf_nick + mlen_nick;
			len_nick = 0;
		}

		if((mlen_uid + len_uid + IDLEN + 3) > (BUFSIZE - 3))
		{
			*(ptr_uid - 1) = '\0';
			sendto_server(client_p->from, NULL, CAP_TS6, NOCAPS,
				      "%s", buf_uid);
			ptr_uid = buf_uid + mlen_uid;
			len_uid = 0;
		}

		if(keep_new_modes)
		{
			if(fl & CHFL_CHANOP)
			{
				*ptr_nick++ = '@';
				*ptr_uid++ = '@';
				len_nick++;
				len_uid++;
			}
			if(fl & CHFL_VOICE)
			{
				*ptr_nick++ = '+';
				*ptr_uid++ = '+';
				len_nick++;
				len_uid++;
			}
		}

		/* copy the nick to the two buffers */
		len = ircsprintf(ptr_nick, "%s ", target_p->name);
		ptr_nick += len;
		len_nick += len;
		len = ircsprintf(ptr_uid, "%s ", use_id(target_p));
		ptr_uid += len;
		len_uid += len;

		if(!keep_new_modes)
		{
			if(fl & CHFL_CHANOP)
				fl = CHFL_DEOPPED;
			else
				fl = 0;
		}

		if(!IsMember(target_p, chptr))
		{
			add_user_to_channel(chptr, target_p, fl);
			sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
					     target_p->name,
					     target_p->username, target_p->host, parv[2]);
			joins++;
		}

		if(fl & CHFL_CHANOP)
		{
			*mbuf++ = 'o';
			para[pargs++] = target_p->name;

			/* a +ov user.. bleh */
			if(fl & CHFL_VOICE)
			{
				/* its possible the +o has filled up MAXMODEPARAMS, if so, start
				 * a new buffer
				 */
				if(pargs >= MAXMODEPARAMS)
				{
					*mbuf = '\0';
					sendto_channel_local(ALL_MEMBERS, chptr,
							     ":%s MODE %s %s %s %s %s %s",
							     source_p->name, chptr->chname,
							     modebuf,
							     para[0], para[1], para[2], para[3]);
					mbuf = modebuf;
					*mbuf++ = '+';
					para[0] = para[1] = para[2] = para[3] = NULL;
					pargs = 0;
				}

				*mbuf++ = 'v';
				para[pargs++] = target_p->name;
			}
		}
		else if(fl & CHFL_VOICE)
		{
			*mbuf++ = 'v';
			para[pargs++] = target_p->name;
		}

		if(pargs >= MAXMODEPARAMS)
		{
			*mbuf = '\0';
			sendto_channel_local(ALL_MEMBERS, chptr,
					     ":%s MODE %s %s %s %s %s %s",
					     source_p->name,
					     chptr->chname,
					     modebuf, para[0], para[1], para[2], para[3]);
			mbuf = modebuf;
			*mbuf++ = '+';
			para[0] = para[1] = para[2] = para[3] = NULL;
			pargs = 0;
		}

	      nextnick:
		/* p points to the next nick */
		s = p;

		/* if there was a trailing space and p was pointing to it, then we
		 * need to exit.. this has the side effect of breaking double spaces
		 * in an sjoin.. but that shouldnt happen anyway
		 */
		if(s && (*s == '\0'))
			s = p = NULL;

		/* if p was NULL due to no spaces, s wont exist due to the above, so
		 * we cant check it for spaces.. if there are no spaces, then when
		 * we next get here, s will be NULL
		 */
		if(s && ((p = strchr(s, ' ')) != NULL))
		{
			*p++ = '\0';
		}
	}

	*mbuf = '\0';
	if(pargs)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s MODE %s %s %s %s %s %s",
				     source_p->name, chptr->chname, modebuf,
				     para[0], CheckEmpty(para[1]), CheckEmpty(para[2]), CheckEmpty(para[3]));
	}

	if(!joins)
	{
		if(isnew)
			destroy_channel(chptr);

		return 0;
	}

	*(ptr_nick - 1) = '\0';
	*(ptr_uid - 1) = '\0';

	sendto_server(client_p->from, NULL, CAP_TS6, NOCAPS,
		      "%s", buf_uid);
	sendto_server(client_p->from, NULL, NOCAPS, CAP_TS6,
		      "%s", buf_nick);

	/* if the source does TS6 we have to remove our bans.  Its now safe
	 * to issue -b's to the non-ts6 servers, as the sjoin we've just
	 * sent will kill any ops they have.
	 */
	if(!keep_our_modes && source_p->id[0] != '\0')
	{
		if(dlink_list_length(&chptr->banlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->banlist,
					'b', NOCAPS, ALL_MEMBERS);

		if(dlink_list_length(&chptr->exceptlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->exceptlist,
					'e', CAP_EX, ONLY_CHANOPS);

		if(dlink_list_length(&chptr->invexlist) > 0)
			remove_ban_list(chptr, source_p, &chptr->invexlist,
					'I', CAP_IE, ONLY_CHANOPS);

		chptr->bants++;
	}

	
	return 0;
}

struct mode_letter
{
	int mode;
	char letter;
};

static struct mode_letter flags[] = {
	{MODE_NOPRIVMSGS,	'n'},
	{MODE_TOPICLIMIT,	't'},
	{MODE_SECRET,		's'},
	{MODE_MODERATED,	'm'},
	{MODE_INVITEONLY,	'i'},
	{MODE_PRIVATE,		'p'},
#ifdef ENABLE_SERVICES
	{MODE_REGONLY,		'r'},
#endif
	{0,			0}
};

static void
set_final_mode(struct Mode *mode, struct Mode *oldmode)
{
	int dir = MODE_QUERY;
	char *pbuf = parabuf;
	int len;
	int i;

	/* ok, first get a list of modes we need to add */
	for (i = 0; flags[i].letter; i++)
	{
		if((mode->mode & flags[i].mode) && !(oldmode->mode & flags[i].mode))
		{
			if(dir != MODE_ADD)
			{
				*mbuf++ = '+';
				dir = MODE_ADD;
			}
			*mbuf++ = flags[i].letter;
		}
	}

	/* now the ones we need to remove. */
	for (i = 0; flags[i].letter; i++)
	{
		if((oldmode->mode & flags[i].mode) && !(mode->mode & flags[i].mode))
		{
			if(dir != MODE_DEL)
			{
				*mbuf++ = '-';
				dir = MODE_DEL;
			}
			*mbuf++ = flags[i].letter;
		}
	}

	if(oldmode->limit && !mode->limit)
	{
		if(dir != MODE_DEL)
		{
			*mbuf++ = '-';
			dir = MODE_DEL;
		}
		*mbuf++ = 'l';
	}
	if(oldmode->key[0] && !mode->key[0])
	{
		if(dir != MODE_DEL)
		{
			*mbuf++ = '-';
			dir = MODE_DEL;
		}
		*mbuf++ = 'k';
		len = ircsprintf(pbuf, "%s ", oldmode->key);
		pbuf += len;
		pargs++;
	}
	if(mode->limit && oldmode->limit != mode->limit)
	{
		if(dir != MODE_ADD)
		{
			*mbuf++ = '+';
			dir = MODE_ADD;
		}
		*mbuf++ = 'l';
		len = ircsprintf(pbuf, "%d ", mode->limit);
		pbuf += len;
		pargs++;
	}
	if(mode->key[0] && strcmp(oldmode->key, mode->key))
	{
		if(dir != MODE_ADD)
		{
			*mbuf++ = '+';
			dir = MODE_ADD;
		}
		*mbuf++ = 'k';
		len = ircsprintf(pbuf, "%s ", mode->key);
		pbuf += len;
		pargs++;
	}
	*mbuf = '\0';
}

/*
 * remove_our_modes
 *
 * inputs	-
 * output	- 
 * side effects	- 
 */
static void
remove_our_modes(struct Channel *chptr, struct Client *source_p)
{
	struct membership *msptr;
	dlink_node *ptr;
	char lmodebuf[MODEBUFLEN];
	const char *lpara[MAXMODEPARAMS];
	int count = 0;
	int i;

	mbuf = lmodebuf;
	*mbuf++ = '-';

	for(i = 0; i < MAXMODEPARAMS; i++)
		lpara[i] = NULL;

	DLINK_FOREACH(ptr, chptr->members.head)
	{
		msptr = ptr->data;

		if(is_chanop(msptr))
		{
			msptr->flags &= ~CHFL_CHANOP;
			lpara[count++] = msptr->client_p->name;
			*mbuf++ = 'o';

			/* +ov, might not fit so check. */
			if(is_voiced(msptr))
			{
				if(count >= MAXMODEPARAMS)
				{
					*mbuf = '\0';
					sendto_channel_local(ALL_MEMBERS, chptr,
							     ":%s MODE %s %s %s %s %s %s",
							     me.name, chptr->chname,
							     lmodebuf, lpara[0], lpara[1],
							     lpara[2], lpara[3]);

					/* preserve the initial '-' */
					mbuf = lmodebuf;
					*mbuf++ = '-';
					count = 0;

					for(i = 0; i < MAXMODEPARAMS; i++)
						lpara[i] = NULL;
				}

				msptr->flags &= ~CHFL_VOICE;
				lpara[count++] = msptr->client_p->name;
				*mbuf++ = 'v';
			}
		}
		else if(is_voiced(msptr))
		{
			msptr->flags &= ~CHFL_VOICE;
			lpara[count++] = msptr->client_p->name;
			*mbuf++ = 'v';
		}
		else
			continue;

		if(count >= MAXMODEPARAMS)
		{
			*mbuf = '\0';
			sendto_channel_local(ALL_MEMBERS, chptr,
					     ":%s MODE %s %s %s %s %s %s",
					     me.name, chptr->chname, lmodebuf,
					     lpara[0], lpara[1], lpara[2], lpara[3]);
			mbuf = lmodebuf;
			*mbuf++ = '-';
			count = 0;

			for(i = 0; i < MAXMODEPARAMS; i++)
				lpara[i] = NULL;
		}
	}

	if(count != 0)
	{
		*mbuf = '\0';
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s MODE %s %s %s %s %s %s",
				     me.name, chptr->chname, lmodebuf,
				     EmptyString(lpara[0]) ? "" : lpara[0],
				     EmptyString(lpara[1]) ? "" : lpara[1],
				     EmptyString(lpara[2]) ? "" : lpara[2],
				     EmptyString(lpara[3]) ? "" : lpara[3]);

	}
}

/* remove_ban_list()
 *
 * inputs	- channel, source, list to remove, char of mode, caps needed
 * outputs	-
 * side effects - given list is removed, with modes issued to local clients
 * 		  and non-TS6 servers.
 */
static void
remove_ban_list(struct Channel *chptr, struct Client *source_p,
		dlink_list *list, char c, int cap, int mems)
{
	static char lmodebuf[BUFSIZE];
	static char lparabuf[BUFSIZE];
	struct Ban *banptr;
	dlink_node *ptr;
	dlink_node *next_ptr;
	char *pbuf;
	int count = 0;
	int cur_len, mlen, plen;

	pbuf = lparabuf;

	cur_len = mlen = ircsprintf(lmodebuf, ":%s MODE %s -", 
				    source_p->name, chptr->chname);
	mbuf = lmodebuf + mlen;

	DLINK_FOREACH_SAFE(ptr, next_ptr, list->head)
	{
		banptr = ptr->data;

		/* trailing space, and the mode letter itself */
		plen = strlen(banptr->banstr) + 2;

		if(count >= MAXMODEPARAMS || (cur_len + plen) > BUFSIZE - 4)
		{
			/* remove trailing space */
			*mbuf = '\0';
			*(pbuf - 1) = '\0';

			sendto_channel_local(mems, chptr, "%s %s",
					     lmodebuf, lparabuf);
			sendto_server(source_p, chptr, cap, CAP_TS6,
				      "%s %s", lmodebuf, lparabuf);

			cur_len = mlen;
			mbuf = lmodebuf + mlen;
			pbuf = lparabuf;
			count = 0;
		}

		*mbuf++ = c;
		cur_len += plen;
		pbuf += ircsprintf(pbuf, "%s ", banptr->banstr);
		count++;

		free_ban(banptr);
	}

	*mbuf = '\0';
	*(pbuf - 1) = '\0';
	sendto_channel_local(mems, chptr, "%s %s", lmodebuf, lparabuf);
	sendto_server(source_p, chptr, cap, CAP_TS6,
		      "%s %s", lmodebuf, lparabuf);

	list->head = list->tail = NULL;
	list->length = 0;
}
