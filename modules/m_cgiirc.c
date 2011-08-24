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

#include "hostmask.h"		/* HM_HOST, HM_IPV4, HM_IPV6, parse_netmask, find_address_conf */

#include "s_user.h"		/* valid_username, valid_hostname */

#include "irc_string.h"		/* strlcpy */

#include "s_conf.h"		/* client_check_cb */

#include "numeric.h"		/* form_str */

static void mr_cgiirc(struct Client*, struct Client*, int, char**);

struct Message cgiirc_msgtab = {
  "WEBIRC", 0, 0, 5, 0, MFLG_SLOW | MFLG_UNREG, 0,
  {mr_cgiirc, m_registered, m_ignore, m_ignore, m_registered, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
  mod_add_cmd(&cgiirc_msgtab);
}

void
_moddeinit(void)
{
  mod_del_cmd(&cgiirc_msgtab);
}

const char *_version = "$Revision: 1.0 $";
#endif

/*
** mr_cgiirc
**      parv[0] = sender prefix
**      parv[1] = cgi password
**      parv[2] = "cgiirc"
**      parv[3] = client hostname
**      parv[4] = client IP address
*/
static void mr_cgiirc(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	char *password = parv[1];
	char non_ident[USERLEN + 1] = { '~', '\0' }; 
	struct AccessItem *aconf = NULL;
	int hosttype = HM_HOST;
	struct irc_ssaddr haddr;
	int bits;
	
	if(parc < 5)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, me.name, "WEBIRC");
		return;
	}

	if((source_p->localClient->registration & REG_INIT) < 3)
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, me.name, "WEBIRC", "Registration already in progress");
		return;
	}

	if(strlen(parv[2]) > USERLEN || !*parv[2] || !valid_username(parv[2]))
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, me.name, "WEBIRC", "Malformed CGI:IRC command");
		exit_client(source_p, &me, "Malformed CGI:IRC command"); 
		return;
	}
	strlcpy(source_p->username, parv[2], sizeof(source_p->username));
	MyFree(source_p->localClient->passwd);
	if(strlen(password) > PASSWDLEN)
		password[PASSWDLEN] = '\0';
	DupString(source_p->localClient->passwd, password); 	
	if(IsGotId(source_p))	{
		aconf = find_address_conf(source_p->host, source_p->username,
					  &source_p->localClient->ip,
					  source_p->localClient->aftype,
					  source_p->localClient->passwd,
					  source_p->certfp);
	}
	else
	{
		strlcpy(non_ident + 1, parv[2], sizeof(non_ident) - 1);
		aconf = find_address_conf(source_p->host, non_ident,
					  &source_p->localClient->ip,
					  source_p->localClient->aftype,
					  source_p->localClient->passwd,
					  source_p->certfp);
	} 	
	
	if((!aconf) || (!aconf->class_ptr) || (!IsConfClient(aconf)) || (!IsConfWebIrc(aconf)) ||
	   IsConfRedir(aconf) || IsConfIllegal(aconf) || IsConfKill(aconf) || IsConfGline(aconf))	   
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, me.name, "WEBIRC", "CGI:IRC authentication failed");
		exit_client(source_p, &me, "CGI:IRC authentication failed"); 
		return; 	
	}

	if(!EmptyString(aconf->passwd))
	{
		if(!match_conf_password(password, aconf))
		{
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, me.name);
			exit_client(source_p, &me, "Bad CGI:IRC Password");
			return;
		}
	} 

	if(strlen(parv[3]) > HOSTLEN || !*parv[3] || !valid_hostname(parv[3]))
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, me.name, "WEBIRC", "Invalid client hostname");
		exit_client(source_p, &me, "Invalid client hostname"); 
		return;	
	}

	hosttype = parse_netmask(parv[4], &haddr, &bits);
	switch(hosttype)
	{
		case HM_IPV4:
			source_p->localClient->aftype = AF_INET; 
			break;
		case HM_IPV6:
			source_p->localClient->aftype = AF_INET6;  
			break;
		default:
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, me.name, "WEBIRC", "Invalid client IP");
			exit_client(source_p, &me, "Invalid client IP"); 
			return;	
	}

	strlcpy(source_p->localClient->cgisockhost, source_p->sockhost, sizeof(source_p->localClient->cgisockhost)); 
	parse_netmask(parv[4], &source_p->localClient->ip, &bits);
	strlcpy(source_p->host, parv[3], sizeof(source_p->host));
	strlcpy(source_p->realhost, parv[3], sizeof(source_p->realhost)); 
	strlcpy(source_p->sockhost, parv[4], sizeof(source_p->sockhost)); 
	SetWebIrc(source_p);
	sendto_one(source_p, ":%s NOTICE AUTH :*** CGI:IRC Host spoofing active", me.name);
}


