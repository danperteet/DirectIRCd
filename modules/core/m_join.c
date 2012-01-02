/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_join.c: Joins a channel.
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
 *  $Id: m_join.c 23507 2007-01-22 18:12:25Z jilles $
 */

#include "stdinc.h"
#include "tools.h"
#include "channel.h"
#include "client.h"
#include "common.h"
#include "hash.h"
#include "irc_string.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_serv.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "sprintf_irc.h"
#include "packet.h"

static int m_join(struct Client *, struct Client *, int, const char **);
static int ms_join(struct Client *, struct Client *, int, const char **);

struct Message join_msgtab = {
	"JOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_join, 2}, {ms_join, 2}, mg_ignore, mg_ignore, {m_join, 2}}
};

mapi_clist_av1 join_clist[] = { &join_msgtab, NULL };
DECLARE_MODULE_AV1(join, NULL, NULL, join_clist, NULL, NULL, "$Revision: 23507 $");

static void do_join_0(struct Client *client_p, struct Client *source_p);
static int check_channel_name_loc(struct Client *source_p, const char *name);

static void set_final_mode(struct Mode *mode, struct Mode *oldmode);
static void remove_our_modes(struct Channel *chptr, struct Client *source_p);

static char modebuf[MODEBUFLEN];
static char parabuf[MODEBUFLEN];
static char *mbuf;

/*
 * m_join
 *      parv[0] = sender prefix
 *      parv[1] = channel
 *      parv[2] = channel password (key)
 */
static int
m_join(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static char jbuf[BUFSIZE];
	struct Channel *chptr = NULL;
	struct ConfItem *aconf;
	char *name;
	char *key = NULL;
	int i, flags = 0;
	char *p = NULL, *p2 = NULL;
	char *chanlist;
	char *mykey;
	int successful_join_count = 0;	/* Number of channels successfully joined */

	jbuf[0] = '\0';

	/* rebuild the list of channels theyre supposed to be joining.
	 * this code has a side effect of losing keys, but..
	 */
	chanlist = LOCAL_COPY(parv[1]);
	for(name = strtoken(&p, chanlist, ","); name;
	    name = strtoken(&p, NULL, ","))
	{
		/* check the length and name of channel is ok */
		if(!check_channel_name_loc(source_p, name) || (strlen(name) > LOC_CHANNELLEN))
		{
			sendto_one_numeric(source_p, ERR_BADCHANNAME,
					   form_str(ERR_BADCHANNAME),
					   (unsigned char *) name);
			continue;
		}

		/* join 0 parts all channels */
		if(*name == '0' && !atoi(name))
		{
			(void) strcpy(jbuf, "0");
			continue;
		}

		/* check it begins with # or &, and local chans are disabled */
		else if(!IsChannelName(name))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
					   form_str(ERR_NOSUCHCHANNEL), name);
			continue;
		}

		/* see if its resv'd */
		if(!IsExemptResv(source_p) && (aconf = hash_find_resv(name)))
		{
			sendto_one_numeric(source_p, ERR_BADCHANNAME,
					form_str(ERR_BADCHANNAME), name);

			/* dont warn for opers */
			if(!IsExemptJupe(source_p) && !IsOper(source_p))
				sendto_realops_flags(UMODE_SPY, L_ALL,
					     "User %s (%s@%s) is attempting to join locally juped channel %s (%s)",
					     source_p->name, source_p->username, source_p->host,
					     name, aconf->passwd);
			/* dont update tracking for jupe exempt users, these
			 * are likely to be spamtrap leaves
			 */
			else if(IsExemptJupe(source_p))
				aconf->port--;

			continue;
		}

		if(splitmode && !IsOper(source_p) && (*name != '&') &&
		   ConfigChannel.no_join_on_split)
		{
			sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
				   me.name, source_p->name, name);
			continue;
		}

		if(*jbuf)
			(void) strcat(jbuf, ",");
		(void) strlcat(jbuf, name, sizeof(jbuf));
	}

	if(parc > 2)
	{
		mykey = LOCAL_COPY(parv[2]);
		key = strtoken(&p2, mykey, ",");
	}

	for(name = strtoken(&p, jbuf, ","); name;
	    key = (key) ? strtoken(&p2, NULL, ",") : NULL, name = strtoken(&p, NULL, ","))
	{
		/* JOIN 0 simply parts all channels the user is in */
		if(*name == '0' && !atoi(name))
		{
			if(source_p->user->channel.head == NULL)
				continue;

			do_join_0(&me, source_p);
			continue;
		}

		/* look for the channel */
		if((chptr = find_channel(name)) != NULL)
		{
			if(IsMember(source_p, chptr))
				continue;
		
			if(dlink_list_length(&chptr->members) == 0)
				flags = CHFL_CHANOP;
			else
				flags = 0;
		}
		else
		{
			if(splitmode && !IsOper(source_p) && (*name != '&') &&
			   ConfigChannel.no_create_on_split)
			{
				sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
					   me.name, source_p->name, name);
				continue;
			}

			flags = CHFL_CHANOP;
		}

		if((dlink_list_length(&source_p->user->channel) >= 
					(unsigned long)ConfigChannel.max_chans_per_user) &&
		   (!IsOper(source_p) || 
		    (dlink_list_length(&source_p->user->channel) >=
				 (unsigned long)ConfigChannel.max_chans_per_user * 3)))
		{
			sendto_one(source_p, form_str(ERR_TOOMANYCHANNELS),
				   me.name, source_p->name, name);
			if(successful_join_count)
				source_p->localClient->last_join_time = CurrentTime;
			return 0;
		}

		if(flags == 0)	/* if channel doesn't exist, don't penalize */
			successful_join_count++;

		if(chptr == NULL)	/* If I already have a chptr, no point doing this */
		{
			chptr = get_or_create_channel(source_p, name, NULL);

			if(chptr == NULL)
			{
				sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
					   me.name, source_p->name, name);
				if(successful_join_count > 0)
					successful_join_count--;
				continue;
			}
		}

		if(!IsOper(source_p) && !IsExemptSpambot(source_p))
			check_spambot_warning(source_p, name);

		/* can_join checks for +i key, bans etc */
		if((i = can_join(source_p, chptr, key)))
		{
			sendto_one(source_p, form_str(i),
				   me.name, source_p->name, name);
			if(successful_join_count > 0)
				successful_join_count--;
			continue;
		}

		/* add the user to the channel */
		add_user_to_channel(chptr, source_p, flags);

		/* we send the user their join here, because we could have to
		 * send a mode out next.
		 */
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);

		/* its a new channel, set +nt and burst. */
		if(flags & CHFL_CHANOP)
		{
			chptr->channelts = CurrentTime;
			chptr->mode.mode |= MODE_TOPICLIMIT;
			chptr->mode.mode |= MODE_NOPRIVMSGS;

			sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s +nt",
					     me.name, chptr->chname);

			if(*chptr->chname == '#')
			{
				sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
					      ":%s SJOIN %ld %s +nt :@%s",
					      me.id, (long) chptr->channelts,
					      chptr->chname, source_p->id);
				sendto_server(client_p, chptr, NOCAPS, CAP_TS6,
					      ":%s SJOIN %ld %s +nt :@%s",
					      me.name, (long) chptr->channelts,
					      chptr->chname, source_p->name);
			}
		}
		else
		{
			sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
				      ":%s JOIN %ld %s +",
				      use_id(source_p), (long) chptr->channelts,
				      chptr->chname);

			sendto_server(client_p, chptr, NOCAPS, CAP_TS6,
				      ":%s SJOIN %ld %s + :%s",
				      me.name, (long) chptr->channelts,
				      chptr->chname, source_p->name);
		}

		del_invite(chptr, source_p);

		if(chptr->topic != NULL)
		{
			sendto_one(source_p, form_str(RPL_TOPIC), me.name,
				   source_p->name, chptr->chname, chptr->topic);

			sendto_one(source_p, form_str(RPL_TOPICWHOTIME),
				   me.name, source_p->name, chptr->chname,
				   chptr->topic_info, chptr->topic_time);
		}

		channel_member_names(chptr, source_p, 1);

		if(successful_join_count)
			source_p->localClient->last_join_time = CurrentTime;
	}

	return 0;
}

/*
 * ms_join
 *
 * inputs	-
 * output	- none
 * side effects	- handles remote JOIN's sent by servers. In TSora
 *		  remote clients are joined using SJOIN, hence a 
 *		  JOIN sent by a server on behalf of a client is an error.
 *		  here, the initial code is in to take an extra parameter
 *		  and use it for the TimeStamp on a new channel.
 */
static int
ms_join(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	static struct Mode mode;
	time_t oldts;
	time_t newts;
	int isnew;
	int keep_our_modes = YES;
	int keep_new_modes = YES;

	/* special case for join 0 */
	if((parv[1][0] == '0') && (parv[1][1] == '\0') && parc == 2)
	{
		do_join_0(client_p, source_p);
		return 0;
	}

	if(parc < 4)
		return 0;

	if(!IsChannelName(parv[2]) || !check_channel_name(parv[2]))
		return 0;

	/* joins for local channels cant happen. */
	if(parv[2][0] == '&')
		return 0;

	mbuf = modebuf;
	mode.key[0] = '\0';
	mode.mode = mode.limit = 0;

	if((chptr = get_or_create_channel(source_p, parv[2], &isnew)) == NULL)
		return 0;

	newts = atol(parv[1]);
	oldts = chptr->channelts;

	/* making a channel TS0 */
	if(!isnew && !newts && oldts)
	{
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to 0",
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

	/* Lost the TS, other side wins, so remove modes on this side */
	if(!keep_our_modes)
	{
		set_final_mode(&mode, &chptr->mode);
		chptr->mode = mode;
		remove_our_modes(chptr, source_p);
		sendto_channel_local(ALL_MEMBERS, chptr,
				     ":%s NOTICE %s :*** Notice -- TS for %s changed from %ld to %ld",
				     me.name, chptr->chname, chptr->chname, (long) oldts, (long) newts);
		if(*modebuf != '\0')
			sendto_channel_local(ALL_MEMBERS, chptr,
					     ":%s MODE %s %s %s",
					     source_p->servptr->name,
					     chptr->chname, modebuf, parabuf);
		*modebuf = *parabuf = '\0';
	}

	if(!IsMember(source_p, chptr))
	{
		add_user_to_channel(chptr, source_p, CHFL_PEON);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
				     source_p->name, source_p->username,
				     source_p->host, chptr->chname);
	}

	sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
		      ":%s JOIN %ld %s +",
		      source_p->id, (long) chptr->channelts, chptr->chname);
	sendto_server(client_p, chptr, NOCAPS, CAP_TS6,
		      ":%s SJOIN %ld %s %s :%s",
		      source_p->servptr->name, (long) chptr->channelts,
		      chptr->chname, keep_new_modes ? "+" : "0",
		      source_p->name);
	return 0;
}

/*
 * do_join_0
 *
 * inputs	- pointer to client doing join 0
 * output	- NONE
 * side effects	- Use has decided to join 0. This is legacy
 *		  from the days when channels were numbers not names. *sigh*
 *		  There is a bunch of evilness necessary here due to
 * 		  anti spambot code.
 */
static void
do_join_0(struct Client *client_p, struct Client *source_p)
{
	struct membership *msptr;
	struct Channel *chptr = NULL;
	dlink_node *ptr;

	/* Finish the flood grace period... */
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);


	sendto_server(client_p, NULL, NOCAPS, NOCAPS, ":%s JOIN 0", source_p->name);

	if(source_p->user->channel.head && MyConnect(source_p) && 
	   !IsOper(source_p) && !IsExemptSpambot(source_p))
		check_spambot_warning(source_p, NULL);

	while ((ptr = source_p->user->channel.head))
	{
		msptr = ptr->data;
		chptr = msptr->chptr;
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
		remove_user_from_channel(msptr);
	}
}

static int
check_channel_name_loc(struct Client *source_p, const char *name)
{
	s_assert(name != NULL);
	if(EmptyString(name))
		return 0;

	if(ConfigFileEntry.disable_fake_channels && !IsOper(source_p))
	{
		for (; *name; ++name)
		{
			if(!IsChanChar(*name) || IsFakeChanChar(*name))
				return 0;
		}
	}
	else
	{
		for(; *name; ++name)
		{
			if(!IsChanChar(*name))
				return 0;
		}
	}

	return 1;
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
