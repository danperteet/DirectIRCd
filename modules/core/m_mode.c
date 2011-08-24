/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_mode.c: Sets a user or channel mode.
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
 *  $Id: m_mode.c 469 2007-03-17 02:59:20Z jon $
 */

#include "stdinc.h"
#include "tools.h"
#include "handlers.h"
#include "channel.h"
#include "channel_mode.h"
#include "client.h"
#include "hash.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "ircd.h"
#include "numeric.h"
#include "s_user.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "packet.h"
#include "common.h"

static void m_mode(struct Client *, struct Client *, int, char *[]);
static void ms_tmode(struct Client *, struct Client *, int, char *[]);
static void ms_bmask(struct Client *, struct Client *, int, char *[]);
static int check_rban(struct Client *client_p, struct Client *source_p, int parc, char *parv[]);


struct Message mode_msgtab = {
	"MODE", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_unregistered, m_mode, m_mode, m_ignore, m_mode, m_ignore}
};

struct Message tmode_msgtab = {
	"TMODE", 0, 0, 4, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, ms_tmode, m_ignore, m_ignore, m_ignore}
};

struct Message bmask_msgtab = {
	"BMASK", 0, 0, 5, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, ms_bmask, m_ignore, m_ignore, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&mode_msgtab);
	mod_add_cmd(&tmode_msgtab);
	mod_add_cmd(&bmask_msgtab);
}

void
_moddeinit(void)
{
	mod_del_cmd(&mode_msgtab);
	mod_del_cmd(&tmode_msgtab);
	mod_del_cmd(&bmask_msgtab);
}

const char *_version = "$Revision: 469 $";
#endif

/*
 * m_mode - MODE command handler
 * parv[0] - sender
 * parv[1] - channel
 */
static void
m_mode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Channel *chptr = NULL;
	struct Membership *member;
	static char modebuf[MODEBUFLEN];
	static char parabuf[MODEBUFLEN];

	if(*parv[1] == '\0')
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "MODE");
		return;
	}

	/* Now, try to find the channel in question */
	if(!IsChanPrefix(*parv[1]))
	{
		/* if here, it has to be a non-channel name */
		set_user_mode(client_p, source_p, parc, parv);
		return;
	}

	if(!check_channel_name(parv[1], !!MyConnect(source_p)))
	{
		sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name, source_p->name, parv[1]);
		return;
	}

	chptr = hash_find_channel(parv[1]);

	if(chptr == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHCHANNEL),
			   ID_or_name(&me, source_p->from),
			   ID_or_name(source_p, source_p->from), parv[1]);
		return;
	}

	switch(check_rban(client_p, source_p, parc, parv))
	{
	case 0:
	case 1:
		break;
	default:
		return;
	}

	/* Now known the channel exists */
	if(parc < 3)
	{
		channel_modes(chptr, source_p, modebuf, parabuf);
		sendto_one(source_p, form_str(RPL_CHANNELMODEIS),
			   me.name, source_p->name, chptr->chname, modebuf, parabuf);
		sendto_one(source_p, form_str(RPL_CREATIONTIME),
			   me.name, source_p->name, chptr->chname, chptr->channelts);
	}
	/* bounce all modes from people we deop on sjoin
	 * servers have always gotten away with murder,
	 * including telnet servers *g* - Dianora
	 *
	 * XXX Is it worth the bother to make an ms_mode() ? - Dianora
	 */
	else if(IsServer(source_p) || IsServices(source_p))
	{
		set_channel_mode(client_p, source_p, chptr, NULL, parc - 2, parv + 2,
				 chptr->chname);
	}
	else
	{
		member = find_channel_link(source_p, chptr);

		if(!has_member_flags(member, CHFL_DEOPPED))
		{
			/* Finish the flood grace period... */
			if(MyClient(source_p) && !IsFloodDone(source_p))
			{
				if(!((parc == 3) && (parv[2][0] == 'b') && (parv[2][1] == '\0')))
					flood_endgrace(source_p);
			}

			set_channel_mode(client_p, source_p, chptr, member, parc - 2, parv + 2,
					 chptr->chname);
		}
	}
}

/*
 * ms_tmode()
 *
 * inputs	- parv[0] = UID
 *		  parv[1] = TS
 *		  parv[2] = channel name
 *		  parv[3] = modestring
 */
static void
ms_tmode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Channel *chptr = NULL;
	struct Membership *member = NULL;

	if((chptr = hash_find_channel(parv[2])) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHCHANNEL),
			   ID_or_name(&me, client_p), ID_or_name(source_p, client_p), parv[2]);
		return;
	}

	if(atol(parv[1]) > chptr->channelts)
		return;

	if(IsServer(source_p) || IsServices(source_p))
		set_channel_mode(client_p, source_p, chptr, NULL, parc - 3, parv + 3,
				 chptr->chname);
	else
	{
		member = find_channel_link(source_p, chptr);

		/* XXX are we sure we just want to bail here? */
		if(has_member_flags(member, CHFL_DEOPPED))
			return;

		set_channel_mode(client_p, source_p, chptr, member, parc - 3, parv + 3,
				 chptr->chname);
	}
}

/*
 * ms_bmask()
 *
 * inputs	- parv[0] = SID
 *		  parv[1] = TS
 *		  parv[2] = channel name
 *		  parv[3] = type of ban to add ('b' 'I' or 'e')
 *		  parv[4] = space delimited list of masks to add
 * outputs	- none
 * side effects	- propagates unchanged bmask line to CAP_TS6 servers,
 *		  sends plain modes to the others.  nothing is sent
 *		  to the server the issuing server is connected through
 */
static void
ms_bmask(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	static char modebuf[IRCD_BUFSIZE];
	static char parabuf[IRCD_BUFSIZE];
	static char banbuf[IRCD_BUFSIZE];
	struct Channel *chptr;
	char *s, *t, *mbuf, *pbuf;
	long mode_type;
	int mlen, tlen;
	int modecount = 0;
	int needcap = NOCAPS;

	if((chptr = hash_find_channel(parv[2])) == NULL)
		return;

	/* TS is higher, drop it. */
	if(atol(parv[1]) > chptr->channelts)
		return;

	switch (*parv[3])
	{
	case 'b':
		mode_type = CHFL_BAN;
		break;

	case 'e':
		mode_type = CHFL_EXCEPTION;
		needcap = CAP_EX;
		break;

	case 'I':
		mode_type = CHFL_INVEX;
		needcap = CAP_IE;
		break;

		/* maybe we should just blindly propagate this? */
	default:
		return;
	}

	parabuf[0] = '\0';
	s = banbuf;
	strlcpy(s, parv[4], sizeof(banbuf));

	/* only need to construct one buffer, for non-ts6 servers */
	mlen = ircsprintf(modebuf, ":%s MODE %s +", source_p->name, chptr->chname);
	mbuf = modebuf + mlen;
	pbuf = parabuf;

	do
	{
		if((t = strchr(s, ' ')) != NULL)
			*t++ = '\0';
		tlen = strlen(s);

		/* I dont even want to begin parsing this.. */
		if(tlen > MODEBUFLEN)
			break;

		if(tlen && *s != ':' && add_id(source_p, chptr, s, mode_type))
		{
			/* this new one wont fit.. */
			if(mbuf - modebuf + 2 + pbuf - parabuf + tlen > IRCD_BUFSIZE - 2 ||
			   modecount >= MAXMODEPARAMS)
			{
				*mbuf = '\0';
				*(pbuf - 1) = '\0';

				sendto_channel_local(ALL_MEMBERS, NO, chptr, "%s %s",
						     modebuf, parabuf);
				sendto_server(client_p, NULL, chptr, needcap, CAP_TS6, NOFLAGS,
					      "%s %s", modebuf, parabuf);

				mbuf = modebuf + mlen;
				pbuf = parabuf;
				modecount = 0;
			}

			*mbuf++ = parv[3][0];
			pbuf += ircsprintf(pbuf, "%s ", s);
			modecount++;
		}

		s = t;
	}
	while(s != NULL);

	if(modecount)
	{
		*mbuf = *(pbuf - 1) = '\0';
		sendto_channel_local(ALL_MEMBERS, NO, chptr, "%s %s", modebuf, parabuf);
		sendto_server(client_p, NULL, chptr, needcap, CAP_TS6, NOFLAGS,
			      "%s %s", modebuf, parabuf);
	}

	/* assumption here is that since the server sent BMASK, they are TS6, so they have an ID */
	sendto_server(client_p, NULL, chptr, CAP_TS6 | needcap, NOCAPS, NOFLAGS,
		      ":%s BMASK %lu %s %s :%s",
		      source_p->id, (unsigned long) chptr->channelts, chptr->chname,
		      parv[3], parv[4]);
}

/*
 * m_rban
 */
static void
m_rban(struct Client *client_p, struct Client *source_p, char *chname, int dir, char *bmask)
{
	struct Channel *chptr = NULL;
	struct Membership *member;
	int alevel;
	mode_count = 0;

	chptr = hash_find_channel(chname);

	if(strlen(bmask) > 200)
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, source_p->name, "MODE", "Regex too long");
		return;
	}
	
	if(!match("r/*", bmask))	
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, source_p->name, "MODE", "Missing regex prefix");
		return;
	}

	if((dir != MODE_ADD) && (dir != MODE_DEL))
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, source_p->name, "MODE", "Direction undefined");
		return;
	}
	
	member = find_channel_link(source_p, chptr);
	alevel = get_channel_access(source_p, member);

	if(alevel < CHACCESS_HALFOP)
	{
		sendto_one(source_p, form_str(alevel == CHACCESS_NOTONCHAN ?
  		           ERR_NOTONCHANNEL : ERR_CHANOPRIVSNEEDED),
			   me.name, source_p->name, chptr->chname);
		return;
	}
	
	switch (dir)
	{
	case MODE_ADD:
		if(!add_id(source_p, chptr, bmask, CHFL_BAN))
			return;
		break;
	case MODE_DEL:
		if(!del_id(chptr, bmask, CHFL_BAN))
			return;
		break;
	default:
		assert(0);
	}

	mode_changes[mode_count].letter = 'b';
	mode_changes[mode_count].dir = dir;
	mode_changes[mode_count].caps = 0;
	mode_changes[mode_count].nocaps = 0;
	mode_changes[mode_count].mems = ALL_MEMBERS;
	mode_changes[mode_count].id = NULL;
	mode_changes[mode_count++].arg = bmask;
	
	send_mode_changes(client_p, source_p, chptr, chptr->chname);
}

static int
check_rban(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	if(parc < 3)
		return 0;

	char *ml = parv[2], c;
	int index = 3;
	int is_rban = 0;
	int has_param_mode = 0;
	int dir = MODE_ADD;
	int rban_index = 0;
	int rban_dir = MODE_QUERY;
	int total = 0;
							
	for(; (c = *ml) != '\0'; ml++)
	{
		total++;
		switch (c)
		{
		case '+':
			dir = MODE_ADD;
			break;
		case '-':
			dir = MODE_DEL;
			break;
		case '=':
			dir = MODE_QUERY;
			break;
		case 'b':
			if(dir == MODE_QUERY)
				break;
			if(index < parc)
			{
				if(match("r/*", parv[index]))
				{
					is_rban++;
					rban_index = index;
					rban_dir = dir;
				}
			}
			index++;
			has_param_mode++;
			break;
		case 'I':
		case 'a':
		case 'e':
		case 'h':
		case 'k':
		case 'l':
		case 'o':
		case 'q':
		case 'v':
			if(dir == MODE_QUERY)
				break;
			index++;
			has_param_mode++;
			break;
		default:
			break;
		}
	}

	if(is_rban)
	{
		if(total > 20)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "MODE", "Channel modes string too long");
			return -1;
		}
		if(is_rban > 1)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "MODE", "You can use only one regex ban per line");
			return -1;
		}
		if(has_param_mode > 1)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "MODE", "You cannot use other parametric modes with regex ban");
			return -1;
		}
		if(ConfigChannel.regex_bans)
		{
			m_rban(client_p, source_p, parv[1], rban_dir, parv[rban_index]);
		}
		else
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "MODE", "Regular expression channel ban system has been disabled");
			return -1;
		}
		return 1;
	}
	return 0;
}

