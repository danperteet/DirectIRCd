/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_protoctl.c: Negotiates capabilities with a irc client.
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
 *  $Id: m_protoctl.c 489 2007-07-04 03:56:19Z jon $
 */

#include "stdinc.h"
#include "handlers.h"
#include "client.h"
#include "irc_string.h"
#include "s_conf.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_user.h"

static void m_protoctl(struct Client *, struct Client *, int, char **);

struct Message protoctl_msgtab = {
	"PROTOCTL", 0, 0, 0, 0, MFLG_SLOW, 0,
	{m_ignore, m_protoctl, m_ignore, m_ignore, m_protoctl, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&protoctl_msgtab);
	add_isupport("NAMESX", NULL, -1);
	add_isupport("UHNAMES", NULL, -1);
}

void
_moddeinit(void)
{
	mod_del_cmd(&protoctl_msgtab);
	delete_isupport("NAMESX");
	delete_isupport("UHNAMES");
}

const char *_version = "$Revision: 489 $";
#endif

/*
 * m_protoctl - PROTOCTL message handler
 *      parv[0] = sender prefix
 *      parv[1] = space-separated list of capabilities
 *
 */
static void
m_protoctl(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	int i;
	char *p = NULL;
	char *s;

	/* ummm, this shouldn't happen. Could argue this should be logged etc. */
	if(client_p->localClient == NULL)
		return;

	for(i = 1; i < parc; i++)
	{
		for(s = strtoken(&p, parv[i], " "); s; s = strtoken(&p, NULL, " "))
		{
			if(!strcmp(s, "NAMESX"))
				client_p->localClient->cap_active |= CAP_MULTI_PREFIX;

			if(!strcmp(s, "UHNAMES"))
				client_p->localClient->cap_active |= CAP_UHNAMES;
		}
	}
}
