/************************************************************************
 *   IRC - Internet Relay Chat, doc/example_module.c
 *   Copyright (C) 2001 Hybrid Development Team
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   $Id: m_cgiirc.c 131 2008-04-17 04:59:29Z Celestin $
 */

#include "stdinc.h"		/* includes setup.h, for STATIC_MODULES */

#include "client.h"		/* Required for IsClient, etc. */

#include "send.h"		/* sendto_one, most useful function of all time */

#include "modules.h"		/* includes msg.h; use for the msgtab */

#include "handlers.h"		/* m_ignore */

#include "hash.h"		/* find_client */

#include "s_serv.h"		/* CAP_ENCAP */

#include "s_conf.h"		/* ConfigFileEntry */

#include "sprintf_irc.h"	/* ircsprintf */

#include "numeric.h"		/* form_str */

#include "irc_string.h"		/* EmptyString */

static void ms_bopm(struct Client*, struct Client*, int, char**);
static void me_bopm(struct Client*, struct Client*, int, char**); 
static void mo_bopm(struct Client*, struct Client*, int, char**);

struct Message bopm_msgtab = {
  "BOPM", 0, 0, 2, 0, MFLG_SLOW | MFLG_UNREG, 0,
  {m_unregistered, m_not_oper, ms_bopm, me_bopm, mo_bopm, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
  mod_add_cmd(&bopm_msgtab);
}

void
_moddeinit(void)
{
  mod_del_cmd(&bopm_msgtab);
}

const char *_version = "$Revision: 1.0 $";
#endif

/*
** mo_bopm
**      parv[0] = BOPM prefix
**      parv[1] = nick
*/
static void mo_bopm(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;	
	char response[NICKLEN * 2 + USERLEN + HOSTLEN + 30]; 

	if(!IsAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if(parc < 2)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "BOPM");
		return;
	}
	
	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHNICK),
			   me.name, source_p->name, parv[1]);
		return;
	} 

	if(!IsClient(target_p))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN),
			   me.name, source_p->name, parv[1]);
		return;
	}

	if(!MyConnect(target_p) && (EmptyString(target_p->sockhost) || !strcmp(target_p->sockhost, "0")) &&
		(!ConfigFileEntry.hide_spoof_ips || !IsIPSpoof(target_p)))
	{
		if(hunt_server(client_p, source_p, ":%s BOPM %s", 1,
			       parc, parv) != HUNTED_ISME)
			return;
	} 

	ircsprintf(response, "%s!%s@%s", target_p->name,
		   target_p->username, ConfigFileEntry.hide_spoof_ips && IsIPSpoof(target_p) ?
		   "255.255.255.255" : target_p->sockhost); 
	sendto_one(source_p, form_str(RPL_USERHOST), me.name, source_p->name, response);
}

/*
** ms_bopm
**      parv[0] = BOPM prefix
**      parv[1] = target nick
*/
static void ms_bopm(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	char response[NICKLEN * 2 + USERLEN + HOSTLEN + 30]; 

	if(parc < 2)
	{
		return;
	}
	
	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
	{
		return;
	} 
	if(!IsClient(target_p) || !IsPrivileged(source_p))
	{
		return;
	}

	if(!MyConnect(target_p) && (EmptyString(target_p->sockhost) || !strcmp(target_p->sockhost, "0")) &&
		(!ConfigFileEntry.hide_spoof_ips || !IsIPSpoof(target_p)))
	{
		if(hunt_server(client_p, source_p, ":%s BOPM %s", 1,
			       parc, parv) != HUNTED_ISME)
			return;
	} 

	ircsprintf(response, "%s!%s@%s", target_p->name,
		   target_p->username, ConfigFileEntry.hide_spoof_ips && IsIPSpoof(target_p) ?
		   "255.255.255.255" : target_p->sockhost); 
	sendto_one(source_p, form_str(RPL_USERHOST), me.name, source_p->name, response);
}

/*
** me_bopm
**      parv[0] = BOPM prefix
**      parv[1] = target nick
**      parv[2] = source nick
*/
static void me_bopm(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	struct Client *sender_p = NULL;
	char response[NICKLEN * 2 + USERLEN + HOSTLEN + 30]; 

	if(!IsServer(source_p))
	{
		return;
	}

	if(parc < 3)
	{
		return;
	}
	
	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
	{
		return;
	} 

	if((sender_p = (struct Client*)find_client(parv[2])) == NULL)
	{
		return;
	} 

	if(!IsClient(target_p))
	{
		return;
	}

	if(!IsClient(sender_p))
	{
		return;
	}

	if(!MyConnect(target_p))
	{
		return;	
	} 

	ircsprintf(response, "%s!%s@%s", target_p->name,
		   target_p->username, ConfigFileEntry.hide_spoof_ips && IsIPSpoof(target_p) ?
		   "255.255.255.255" : target_p->sockhost); 
	sendto_one(sender_p, form_str(RPL_USERHOST), me.name, sender_p->name, response);
}


 

