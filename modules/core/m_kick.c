/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_kick.c: Kicks a user from a channel.
 *
 *  Copyright (C) 2002 by the past and present ircd coders, and others.
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
 *  $Id: m_kick.c 439 2006-08-22 08:14:17Z jon $
 */

#include "stdinc.h"
#include "tools.h"
#include "handlers.h"
#include "channel.h"
#include "channel_mode.h"
#include "common.h"
#include "client.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "parse.h"
#include "hash.h"
#include "packet.h"
#include "s_serv.h"


static void m_kick(struct Client *, struct Client *, int, char *[]);

struct Message kick_msgtab = {
	"KICK", 0, 0, 3, 0, MFLG_SLOW, 0,
	{m_unregistered, m_kick, m_kick, m_ignore, m_kick, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&kick_msgtab);
}

void
_moddeinit(void)
{
	mod_del_cmd(&kick_msgtab);
}

const char *_version = "$Revision: 439 $";
#endif

/* m_kick()
 *  parv[0] = sender prefix
 *  parv[1] = channel
 *  parv[2] = client to kick
 *  parv[3] = kick comment
 */
static void
m_kick(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *who;
	struct Channel *chptr;
	int chasing = 0;
	char *comment;
	char *name;
	char *p = NULL;
	char *user;
	const char *from, *to;
	struct Membership *ms = NULL;
	struct Membership *ms_target;

	if(!MyConnect(source_p) && IsCapable(source_p->from, CAP_TS6) && HasID(source_p))
	{
		from = me.id;
		to = source_p->id;
	}
	else
	{
		from = me.name;
		to = source_p->name;
	}

	if(*parv[2] == '\0')
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), from, to, "KICK");
		return;
	}

	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	comment = (EmptyString(parv[3])) ? parv[2] : parv[3];
	if(strlen(comment) > (size_t) KICKLEN)
		comment[KICKLEN] = '\0';

	name = parv[1];
	while(*name == ',')
		name++;

	if((p = strchr(name, ',')) != NULL)
		*p = '\0';
	if(*name == '\0')
		return;

	if((chptr = hash_find_channel(name)) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHCHANNEL), from, to, name);
		return;
	}

	if(!IsServer(source_p) && !IsServices(source_p))
	{
		if((ms = find_channel_link(source_p, chptr)) == NULL)
		{
			if(MyConnect(source_p))
			{
				sendto_one(source_p, form_str(ERR_NOTONCHANNEL),
					   me.name, source_p->name, name);
				return;
			}
		}

		if(!has_member_flags(ms, CHFL_OWNER | CHFL_PROTECTED | CHFL_CHANOP | CHFL_HALFOP))
		{
			/* was a user, not a server, and user isn't seen as a chanop here */
			if(MyConnect(source_p))
			{
				/* user on _my_ server, with no chanops.. so go away */
				sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
					   me.name, source_p->name, name);
				return;
			}

			if(chptr->channelts == 0)
			{
				/* If its a TS 0 channel, do it the old way */
				sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
					   from, to, name);
				return;
			}

			/* Its a user doing a kick, but is not showing as chanop locally
			 * its also not a user ON -my- server, and the channel has a TS.
			 * There are two cases we can get to this point then...
			 *
			 *     1) connect burst is happening, and for some reason a legit
			 *        op has sent a KICK, but the SJOIN hasn't happened yet or 
			 *        been seen. (who knows.. due to lag...)
			 *
			 *     2) The channel is desynced. That can STILL happen with TS
			 *        
			 *     Now, the old code roger wrote, would allow the KICK to 
			 *     go through. Thats quite legit, but lets weird things like
			 *     KICKS by users who appear not to be chanopped happen,
			 *     or even neater, they appear not to be on the channel.
			 *     This fits every definition of a desync, doesn't it? ;-)
			 *     So I will allow the KICK, otherwise, things are MUCH worse.
			 *     But I will warn it as a possible desync.
			 *
			 *     -Dianora
			 */
		}
	}

	user = parv[2];

	while(*user == ',')
		user++;

	if((p = strchr(user, ',')) != NULL)
		*p = '\0';

	if(*user == '\0')
		return;

	if((who = find_chasing(client_p, source_p, user, &chasing)) == NULL)
		return;

	if((ms_target = find_channel_link(who, chptr)) != NULL)
	{
		/* Only apply restrictions to local clients */
		if(MyClient(source_p))
		{
			/* 
			 * Do not allow services to be kicked by local clients.
			 */
			if(IsServices(who))
			{
				static char buf[IRCD_BUFSIZE];
				ircsprintf(buf, "%s is a %s and cannot be kicked from %s",
					   who->name, "network service", name);
				sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND), me.name,
					   source_p->name, "KICK", buf);
				return;
			}

#ifdef RIZON
			/* 
			 * Do not allow netadmins to be kicked by local clients unless the client
			 * is kicking itself. If an attempt is made on a netadmin report it to
			 * the netadmin.
			 */
			if(IsNetAdmin(who) && source_p != who)
			{
				static char buf[IRCD_BUFSIZE];
				sendto_one(who,
					   ":%s NOTICE %s :*** %s tried to kick you from %s and failed",
					   ID_or_name(&me, who->from), ID_or_name(who, who->from),
					   source_p->name, name);
				ircsprintf(buf, "%s is a %s and cannot be kicked from %s",
					   who->name, "network administrator", name);
				sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND), me.name,
					   source_p->name, "KICK", buf);
				return;
			}
#endif

#ifdef CHANAQ
			/* 
			 * Do not allow local clients to kick a owner or protected user unless
			 * they are a owner, or the source and target are the same.
			 * (client kicking himself)
			 */
			if(has_member_flags(ms_target, CHFL_OWNER | CHFL_PROTECTED)
			   && !has_member_flags(ms, CHFL_OWNER) && source_p != who)
			{
				sendto_one(source_p, form_str(ERR_CHANOWNPRIVNEEDED),
					   me.name, source_p->name, name);
				return;
			}
#endif

#ifdef HALFOPS
			/* half ops cannot kick other halfops on private channels */
			if(has_member_flags(ms, CHFL_HALFOP) && !has_member_flags(ms,
#ifdef CHANAQ
										  CHFL_OWNER |
										  CHFL_PROTECTED |
#endif
										  CHFL_CHANOP))
			{
				if(((chptr->mode.mode & MODE_PRIVATE) &&
				    has_member_flags(ms_target, CHFL_CHANOP | CHFL_HALFOP))
				   || has_member_flags(ms_target, CHFL_CHANOP))
				{
					sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
						   me.name, source_p->name, name);
					return;
				}
			}
#endif
		}

		/* jdc
		 * - In the case of a server kicking a user (i.e. CLEARCHAN),
		 *   the kick should show up as coming from the server which did
		 *   the kick.
		 * - Personally, flame and I believe that server kicks shouldn't
		 *   be sent anyways.  Just waiting for some oper to abuse it...
		 */
		if(IsServer(source_p))
			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s KICK %s %s :%s",
					     source_p->name, name, who->name, comment);
		else
			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s KICK %s %s :%s",
					     source_p->name, source_p->username,
					     source_p->host, name, who->name, comment);

		sendto_server(client_p, NULL, chptr, CAP_TS6, NOCAPS, NOFLAGS,
			      ":%s KICK %s %s :%s", ID(source_p), chptr->chname, ID(who), comment);
		sendto_server(client_p, NULL, chptr, NOCAPS, CAP_TS6, NOFLAGS,
			      ":%s KICK %s %s :%s", source_p->name, chptr->chname,
			      who->name, comment);

		remove_user_from_channel(ms_target);
	}
	else if(MyClient(source_p))
		sendto_one(source_p, form_str(ERR_USERNOTINCHANNEL), from, to, user, name);
}
