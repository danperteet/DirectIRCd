/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_names.c: Shows the users who are online.
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
 *  $Id: m_names.c 489 2007-07-04 03:56:19Z jon $
 */

#include "stdinc.h"
#include "tools.h"
#include "handlers.h"
#include "channel.h"
#include "channel_mode.h"
#include "client.h"
#include "common.h"		/* bleah */
#include "hash.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "ircd.h"
#include "list.h"
#include "numeric.h"
#include "send.h"
#include "s_serv.h"
#include "s_conf.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"


static void m_names(struct Client *, struct Client *, int, char *[]);
static void ms_names(struct Client *, struct Client *, int, char *[]);

struct Message names_msgtab = {
	"NAMES", 0, 0, 0, 0, MFLG_SLOW, 0,
	{m_unregistered, m_names, ms_names, m_ignore, m_names, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&names_msgtab);
}

void
_moddeinit(void)
{
	mod_del_cmd(&names_msgtab);
}

const char *_version = "$Revision: 489 $";
#endif

/************************************************************************
 * m_names() - Added by Jto 27 Apr 1989
 ************************************************************************/

/*
** m_names
**      parv[0] = sender prefix
**      parv[1] = channel
*/
static void
m_names(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Channel *chptr = NULL;
	char *s;
	char *para = parc > 1 ? parv[1] : NULL;

	if(!EmptyString(para))
	{
		while(*para == ',')
			++para;

		if((s = strchr(para, ',')) != NULL)
			*s = '\0';

		if(*para == '\0')
			return;

		if((chptr = hash_find_channel(para)) != NULL)
			channel_member_names(source_p, chptr, 1);
		else
			sendto_one(source_p, form_str(RPL_ENDOFNAMES),
				   me.name, source_p->name, para);
	}
	else
		sendto_one(source_p, form_str(RPL_ENDOFNAMES), me.name, source_p->name, "*");
}

static void
ms_names(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	/* If its running as a hub, and linked with lazy links
	 * then allow leaf to use normal client m_names()
	 * other wise, ignore it.
	 */
	if(ServerInfo.hub)
		if(!IsCapable(client_p->from, CAP_LL))
			return;

	if(IsClient(source_p))
		m_names(client_p, source_p, parc, parv);
}
