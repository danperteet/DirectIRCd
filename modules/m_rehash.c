/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_rehash.c: Re-reads the configuration file.
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
 *  $Id: m_rehash.c 505 2007-07-16 16:47:50Z jon $
 */
/*
 * Portions of this code have been taken from ircd-ratbox, and from jilles'
 * remote rehash patch located at:
 *
 * http://www.stack.nl/~jilles/irc/ratbox-remote-rehash-testing.patch
 */

#include "stdinc.h"
#include "handlers.h"
#include "client.h"
#include "common.h"
#include "irc_string.h"
#include "ircd.h"
#include "list.h"
#include "s_serv.h"
#include "numeric.h"
#include "irc_res.h"
#include "s_conf.h"
#include "s_log.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"

static void me_rehash(struct Client *, struct Client *, int, char **);
static void mo_rehash(struct Client *, struct Client *, int, char **);

struct Message rehash_msgtab = {
	"REHASH", 0, 0, 0, 0, MFLG_SLOW, 0,
	{m_unregistered, m_not_oper, m_ignore, me_rehash, mo_rehash, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&rehash_msgtab);
}

void
_moddeinit(void)
{
	mod_del_cmd(&rehash_msgtab);
}

const char *_version = "$Revision: 505 $";
#endif

struct hash_commands
{
	const char *cmd;
	void (*handler) (struct Client * source_p);
};

#ifndef _WIN32
static void
rehash_dns(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is rehashing DNS", get_oper_name(source_p));

	/* reread /etc/resolv.conf and reopen res socket */
	restart_resolver();
}

static void
rehash_fdlimit(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL, "%s is updating FDLIMIT", get_oper_name(source_p));

	recalc_fdlimit(NULL);
}
#endif

static void
rehash_motd(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s is forcing re-reading of MOTD file", get_oper_name(source_p));

	read_message_file(&ConfigFileEntry.motd);
}

static void
rehash_omotd(struct Client *source_p)
{
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s is forcing re-reading of OPER MOTD file", get_oper_name(source_p));

	read_message_file(&ConfigFileEntry.opermotd);
}

/* *INDENT-OFF* */
static struct hash_commands rehash_commands[] =
{
#ifndef _WIN32
        {"DNS",         rehash_dns              },
	{"FDLIMIT",	rehash_fdlimit		},
#endif
        {"MOTD",        rehash_motd             },
        {"OMOTD",       rehash_omotd            },
        {NULL,          NULL                    }
};
/* *INDENT-ON* */

static void
do_rehash(struct Client *source_p, const char *type)
{
	if(type != NULL)
	{
		int x;
		char cmdbuf[100];

		for(x = 0; rehash_commands[x].cmd != NULL && rehash_commands[x].handler != NULL;
		    x++)
		{
			if(irccmp(type, rehash_commands[x].cmd) == 0)
			{
				sendto_one(source_p, form_str(RPL_REHASHING), me.name,
					   source_p->name, rehash_commands[x].cmd);
				rehash_commands[x].handler(source_p);
				ilog(L_NOTICE, "REHASH %s From %s[%s]", type,
				     get_oper_name(source_p), source_p->sockhost);
				return;
			}
		}

		/* We are still here..we didn't match */
		cmdbuf[0] = '\0';
		for(x = 0; rehash_commands[x].cmd != NULL && rehash_commands[x].handler != NULL;
		    x++)
		{
			strlcat(cmdbuf, " ", sizeof(cmdbuf));
			strlcat(cmdbuf, rehash_commands[x].cmd, sizeof(cmdbuf));
		}
		sendto_one(source_p, ":%s NOTICE %s :rehash one of:%s", me.name, source_p->name,
			   cmdbuf);
	}
	else
	{
		sendto_one(source_p, form_str(RPL_REHASHING), me.name, source_p->name,
			   ConfigFileEntry.configfile);
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "%s is rehashing server config file", get_oper_name(source_p));
		ilog(L_NOTICE, "REHASH From %s[%s]", get_oper_name(source_p), source_p->sockhost);
		rehash(0);
	}
}

/*
 * mo_rehash - REHASH message handler
 *
 * parv[1] = rehash type or destination
 * parv[2] = destination
 */
static void
mo_rehash(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	const char *type = NULL, *target_server = NULL;

	if(!IsOperRehash(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "rehash");
		return;
	}

	if(parc > 2)
		type = parv[1], target_server = parv[2];
	else if(parc > 1 && (strchr(parv[1], '.') || strchr(parv[1], '?') || strchr(parv[1], '*')))
		type = NULL, target_server = parv[1];
	else if(parc > 1)
		type = parv[1], target_server = NULL;
	else
		type = NULL, target_server = NULL;

	if(target_server != NULL)
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return;
		}
		sendto_match_servs(source_p, target_server, CAP_ENCAP,
				   "ENCAP %s REHASH %s", target_server, type != NULL ? type : "");
		if(match(target_server, me.name) == 0)
			return;
	}

	do_rehash(source_p, type);
}

static void
me_rehash(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	if(!IsClient(source_p))
		return;

	if(!find_matching_name_conf(ULINE_TYPE, source_p->servptr->name,
				    source_p->username, source_p->realhost, SHARED_REHASH))
		return;

	do_rehash(source_p, parc > 1 ? parv[1] : NULL);
}
