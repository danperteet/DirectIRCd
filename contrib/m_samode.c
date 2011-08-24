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
 *   $Id: example_module.c 131 2005-12-10 04:59:29Z jon $
 */

/* List of ircd includes from ../include/ 
 * These ones are necessary to build THIS module...
 */

#include "stdinc.h"		/* includes setup.h, for STATIC_MODULES */

#include "client.h"		/* Required for IsClient, etc. */

#include "send.h"		/* sendto_one, most useful function of all time */

#include "modules.h"		/* includes msg.h; use for the msgtab */

#include "handlers.h"		/* m_ignore */

#include "numeric.h"       	/* form_str */

#include "irc_string.h"		/* IsChanPrefix */

#include "hash.h"		/* find_client and hash_find_channel */

#include "channel_mode.h"	/* set_channel_mode */

#include "s_serv.h"		/* CAP_ENCAP */

#include "s_conf.h"		/* ConfigChannel and ConfigFileEntry and detach_conf and OPER_TYPE */

#include "ircd.h"		/* Count and oper_list */

#include "list.h"		/* free_dlink_node */

#include "s_user.h"		/* user_modes and send_umode */

#include "cloak.h"		/* make_virthost */

#include "common.h"		/* #define NO */

#include "hostmask.h"		/* HM_HOST and parse_netmask */

#include "sprintf_irc.h"	/* ircsprintf */

/* OTHER USEFUL INCLUDES:
 * 
 * #include "handlers.h" <-- include this file to be able to use default
 * functions in place of your own 'Access Denied' kind of function
 * 
 * #include "numeric.h" <-- include this file to be able to use form_str,
 * standard message formats (see messages.tab and *.lang in messages/)
 * Examples are strewn all across the ircd code, so just grep a bit to
 * find one!
 *
 * #include "irc_string.h" <-- best to include this if you use *any*
 * string comparison or parsing functions, although they may be available
 * natively for your OS the prototypes in irc_string.h may be required for
 * others. */

/* Declare the void's initially up here, as modules don't have an
 * include file, we will normally have client_p, source_p, parc
 * and parv[] where:
 *
 * client_p == client issuing command
 * source_p == where the command came from
 * parc     == the number of parameters
 * parv     == an array of the parameters
 */
static void mo_sajoin(struct Client *, struct Client *, int, char *[]);
static void me_sajoin(struct Client *, struct Client *, int, char *[]);
static void sajoinloop(struct Client *, struct Client *, int, char *[]);

static void mo_sapart(struct Client *, struct Client *, int, char *[]);
static void me_sapart(struct Client *, struct Client *, int, char *[]);
static void sapartloop(struct Client *, struct Client *, int, char *[]);

static void mo_samode(struct Client *, struct Client *, int, char *[]);
static void mo_saumode(struct Client *, struct Client *, int, char *[]);
static void me_samode(struct Client *, struct Client *, int, char *[]);
static void mo_operup(struct Client *, int parc, char *parv[]);

static void ms_smode(struct Client *, struct Client *, int, char *[]);

static char* last0(struct Client *, struct Client *, char*);
static int check_rban(struct Client *client_p, struct Client *source_p, int parc, char *parv[]);
static void send_sumode_out(struct Client *source_p, unsigned int old);


/*
 * Show the commands this module can handle in a msgtab
 * and give the msgtab a name, here its samode_msgtab
 */
struct Message sajoin_msgtab = {

	"SAJOIN", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_unregistered, m_not_oper, m_ignore, me_sajoin, mo_sajoin, m_ignore}
};

struct Message sapart_msgtab = {

	"SAPART", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_unregistered, m_not_oper, m_ignore, me_sapart, mo_sapart, m_ignore}
};

struct Message samode_msgtab = {

	"SAMODE", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_unregistered, m_not_oper, m_ignore, me_samode, mo_samode, m_ignore}
};

struct Message smode_msgtab = {

	"SMODE", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, ms_smode, m_ignore, m_ignore, m_ignore}
};

/* That's the msgtab finished */

#ifndef STATIC_MODULES
void
_modinit(void)
{
	/* This will add the commands in samode_msgtab (which is above) */
	mod_add_cmd(&sajoin_msgtab);
	mod_add_cmd(&sapart_msgtab);
	mod_add_cmd(&samode_msgtab);
	mod_add_cmd(&smode_msgtab);
}

void
_moddeinit(void)
{
	/* This will remove the commands in samode_msgtab (which is above) */
	mod_del_cmd(&sajoin_msgtab);
	mod_del_cmd(&sapart_msgtab);
	mod_del_cmd(&samode_msgtab);
	mod_del_cmd(&smode_msgtab);
}

const char *_version = "$Revision: 1.0 $";
#endif

/*
 * sajoinloop - loop joining local user to channels with proper flags
 *      parv[1] = nick to join
 *      parv[2] = channels
 */
static void
sajoinloop(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = (struct Client*)find_client(parv[1]);
	struct Client *sajoinerr_p = NULL;
	struct Channel *chptr = NULL; 
	const char *prefix = "";
	char modelettertab[2];
	modelettertab[0] = '\0';
	modelettertab[1] = '\0';
	char *modeletter = modelettertab;
	char *mode[2];
	mode[0] = modelettertab;
	mode[1] = parv[1];
	char *name = last0(target_p, target_p, parv[2]);
	char *t = NULL;
	unsigned int flags = 0;

	for(name = strtoken(&t, name, ","); name; name = strtoken(&t, NULL, ","))
	{
		switch (*name)
		{
		case '@':
			prefix = "@";
			flags = CHFL_CHANOP;
			*modeletter = 'o';
			++name;
			break;
#ifdef HALFOPS
		case '%':
			prefix = "%";
			flags = CHFL_HALFOP;
			*modeletter = 'h';
			++name;
			break;
#endif
		case '+':
			prefix = "+";
			flags = CHFL_VOICE;
			*modeletter = 'v';
			++name;
			break;
#ifdef CHANAQ
		case '~':
			prefix = "~";
			flags = CHFL_OWNER;
			*modeletter = 'q';
			++name;
			break;
		case '!':
			prefix = "&";
			flags = CHFL_PROTECTED;
			*modeletter = 'a';
			++name;
			break;
#endif
		case '&':
		case '#':
			prefix = "";
			flags = 0;
			*modeletter = '\0';
			break;

		default:
			sendto_one(source_p, form_str(ERR_NOSUCHCHANNEL),
				   me.name, source_p->name, name);
			continue;
		}

		/* Error checking here */
		if((chptr = hash_find_channel(name)) == NULL)
		{
			/* channel does not exist so we create new */
			if(!check_channel_name(name, 1))
			{
				sendto_one(source_p, form_str(ERR_BADCHANNAME),
					   me.name, source_p->name, name);
				continue;
			}
			chptr = make_channel(name);
			if(*modeletter != '\0')	
			{		
				add_user_to_channel(chptr, target_p, flags, NO);			
				if(chptr->chname[0] == '#')
				{
					sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS,
						      LL_ICLIENT, ":%s SJOIN %lu %s +nt :%s%s", me.id,
						      (unsigned long) chptr->channelts, chptr->chname,
						      prefix, target_p->id);
					sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6,
						      LL_ICLIENT, ":%s SJOIN %lu %s +nt :%s%s", me.name,
						      (unsigned long) chptr->channelts, chptr->chname,
						      prefix, target_p->name);
				}
			}
			else
			{
				add_user_to_channel(chptr, target_p, CHFL_CHANOP, NO);
				if(chptr->chname[0] == '#')
				{
					sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS,
						      LL_ICLIENT, ":%s SJOIN %lu %s +nt :@%s", me.id,
						      (unsigned long) chptr->channelts, chptr->chname,
						      target_p->id);
					sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6,
						      LL_ICLIENT, ":%s SJOIN %lu %s +nt :@%s", me.name,
						      (unsigned long) chptr->channelts, chptr->chname,
						      target_p->name);
				}
			}
			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s JOIN %s",
					     target_p->name, target_p->username,
					     target_p->host, chptr->chname);
			
			chptr->mode.mode |= MODE_TOPICLIMIT | MODE_NOPRIVMSGS;
			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s MODE %s +nt",
					     me.name, chptr->chname);

			target_p->localClient->last_join_time = CurrentTime;
			channel_member_names(target_p, chptr, 1);
		}
		else if(IsMember(target_p, chptr))
		{
			if(*modeletter != '\0')
				set_channel_mode(target_p, source_p->servptr, chptr, NULL, 2, mode,
						 chptr->chname);
			else { 
				if(IsServer(source_p))
				{
					if(parv[3])
						sajoinerr_p = (struct Client*)find_client(parv[3]);
					if((sajoinerr_p != NULL) && IsOper(sajoinerr_p))
						sendto_one(sajoinerr_p, form_str(ERR_USERONCHANNEL),
				   			   me.name, sajoinerr_p->name, target_p->name, chptr->chname);
				}
				else
					sendto_one(source_p, form_str(ERR_USERONCHANNEL),
			   			   me.name, source_p->name, target_p->name, chptr->chname);
 				continue;
			}	
		}
		else
		{
			add_user_to_channel(chptr, target_p, flags, NO);

			if(chptr->chname[0] == '#')
			{
				sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%s%s", me.id,
					      (unsigned long) chptr->channelts, chptr->chname,
					      prefix, target_p->id);
				sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%s%s", me.name,
					      (unsigned long) chptr->channelts, chptr->chname,
					      prefix, target_p->name);
			}

			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s JOIN %s",
					     target_p->name, target_p->username,
					     target_p->host, chptr->chname);

			if(*modeletter != '\0')
				sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s MODE %s +%c %s",
						     me.name, chptr->chname, *modeletter,
						     target_p->name);

			/* send the topic... */
			if(chptr->topic != NULL)
			{
				sendto_one(target_p, form_str(RPL_TOPIC),
					   me.name, target_p->name, chptr->chname, chptr->topic);
				sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
					   me.name, target_p->name, chptr->chname,
					   chptr->topic_info, chptr->topic_time);
			}

			target_p->localClient->last_join_time = CurrentTime;
			channel_member_names(target_p, chptr, 1);
		}
	}
}

/*
 * me_sajoin - encap server sajoin 
 *      parv[1] = nick to join
 *      parv[2] = channels
 *      parv[3] = oper nick doing sajoin
 */
static void
me_sajoin(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsServer(source_p))
	{
		return;
	}

	if(parc < 4)
	{ 
		return;
	}

	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
	{
		return;
	} 
	
	if(!MyClient(target_p))
	{
		return;
	}

	sajoinloop(client_p,source_p,parc,parv);	
}

/*
 * mo_sajoin - oper client sajoin
 *      parv[1] = nick to join
 *      parv[2] = channels
 */
static void
mo_sajoin(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsNetAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if(parc < 3)
	{ 
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "SAJOIN"); 
		return;
	}

	if(strlen(parv[2]) > 200)
	{
		sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, source_p->name, "SAJOIN", "Channels list is too long");
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

	sendto_server(NULL, source_p, NULL, NOCAPS, NOCAPS, LL_ICLIENT,
		      ":%s OPERWALL :%s used SAJOIN %s %s", me.name, source_p->name, target_p->name, parv[2]);
	sendto_wallops_flags(UMODE_OPERWALL, source_p, "OPERWALL - %s used SAJOIN %s %s", source_p->name, target_p->name, parv[2]); 

	if(!MyConnect(target_p))
	{
		sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
			      LL_ICLIENT, ":%s ENCAP * SAJOIN %s %s %s",
			      me.name, target_p->name, parv[2], source_p->name);
		return;	
	}
	
	sajoinloop(client_p,source_p,parc,parv);	
}

/*
 * sapartloop - loop parting local user from channels
 *      parv[1] = nick to part
 *      parv[2] = channels
 */
static void
sapartloop(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = (struct Client*)find_client(parv[1]);
	struct Channel *chptr = NULL; 
	struct Membership *member = NULL; 
	char *name = parv[2];
	char *t = NULL;

	for(name = strtoken(&t, name, ","); name; name = strtoken(&t, NULL, ","))
	{

		if((chptr = hash_find_channel(name)) == NULL)
			continue;

		if((member = find_channel_link(target_p, chptr)) == NULL)
			continue;

		if(chptr->chname[0] == '#')
		{
			sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS, LL_ICLIENT,
				      ":%s PART %s", target_p->id, chptr->chname);
			sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6, LL_ICLIENT,
				      ":%s PART %s", target_p->name, chptr->chname);
		}

		sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s PART %s",
				     target_p->name, target_p->username, target_p->host, chptr->chname);
		remove_user_from_channel(member);
	}
}

/*
 * me_sapart - encap server sapart
 *      parv[1] = nick to part
 *      parv[2] = channels
 */
static void
me_sapart(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;


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
	
	if(!MyClient(target_p))
	{
		return;	
	}
	
	sapartloop(client_p,source_p,parc,parv);
}

/*
 * mo_sapart - oper client sapart
 *      parv[1] = nick to part
 *      parv[2] = channels
 */
static void
mo_sapart(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsNetAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if(parc < 3)
	{ 
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "SAPART"); 
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

	sendto_server(NULL, source_p, NULL, NOCAPS, NOCAPS, LL_ICLIENT,
		      ":%s OPERWALL :%s used SAPART %s %s", me.name, source_p->name, target_p->name, parv[2]);
	sendto_wallops_flags(UMODE_OPERWALL, source_p, "OPERWALL - %s used SAPART %s %s", source_p->name, target_p->name, parv[2]); 

	if(!MyConnect(target_p))
	{
		sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
			      LL_ICLIENT, ":%s ENCAP * SAPART %s %s",
			      me.name, target_p->name, parv[2]);
		return;	
	}

	sapartloop(client_p,source_p,parc,parv);
}

/*
 * mo_samode
 *      parv[0] = sender prefix
 *      parv[1] = parameter
 */
static void
mo_samode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	struct Channel *chptr = NULL; 
	char chmodesbuf[512]; //parse.c in parse command assumes max command buffer size of 512B
	char *chmodes = chmodesbuf; 
	int i;
	int size = 512;

	if(!IsNetAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if(parc < 3)
	{ 
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "SAMODE"); 
		return;
	}


	if(!IsChanPrefix(*parv[1]))
	{
		/* if here, it has to be a non-channel name */
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

		if(parc < 4)
		{
			sendto_server(NULL, source_p, NULL, NOCAPS, NOCAPS, LL_ICLIENT,
				      ":%s OPERWALL :%s used SAMODE %s %s", me.name, source_p->name, target_p->name, parv[2]);
			sendto_wallops_flags(UMODE_OPERWALL, source_p, "OPERWALL - %s used SAMODE %s %s", source_p->name, target_p->name, parv[2]); 
		}
		else
		{
			sendto_server(NULL, source_p, NULL, NOCAPS, NOCAPS, LL_ICLIENT,
				      ":%s OPERWALL :%s used SAMODE %s %s %s", me.name, source_p->name, target_p->name, parv[2], parv[3]);
			sendto_wallops_flags(UMODE_OPERWALL, source_p, "OPERWALL - %s used SAMODE %s %s %s", source_p->name, target_p->name, parv[2], parv[3]); 
		}

		if(!MyConnect(target_p))
		{
			if(parc < 4)
			{
				sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
					      LL_ICLIENT, ":%s ENCAP * SAMODE %s %s",
					      me.name, target_p->name, parv[2]);
			}
			else
			{
				sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
					      LL_ICLIENT, ":%s ENCAP * SAMODE %s %s %s",
					      me.name, target_p->name, parv[2], parv[3]);
			}
			return;
		}

		mo_saumode(client_p,source_p,parc,parv);
		return;
  	}
	
	if((chptr = (struct Channel*)hash_find_channel(parv[1])) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHCHANNEL),
			   me.name, source_p->name, parv[1]);
		return;
	}
	
	for(i = 3; i < parc; i++)
	{
		chmodes = chmodesbuf;
		size = size - strlcpy(chmodes+512-size,parv[i],size);
		chmodesbuf[512-size] = ' ';
		size--;	
	}		
	if(size > 0)
		chmodesbuf[512-size] = '\0';
	else
		chmodesbuf[511] = '\0';

	switch(check_rban(client_p, source_p, parc, parv))
	{
		case 0:
		case 1:
			break;
		default:
			return;
	}	

	sendto_server(NULL, source_p, NULL, NOCAPS, NOCAPS, LL_ICLIENT,
		      ":%s OPERWALL :%s used SAMODE %s %s %s", me.name, source_p->name, parv[1], parv[2], chmodesbuf);
	sendto_wallops_flags(UMODE_OPERWALL, source_p, "OPERWALL - %s used SAMODE %s %s %s", source_p->name, parv[1], parv[2], chmodesbuf); 

	set_channel_mode(client_p, source_p->servptr, chptr, NULL, parc - 2, parv + 2,
		 chptr->chname); 
}

/*
 * me_samode
 *      parv[0] = sender prefix
 *      parv[1] = parameter
 */
static void
me_samode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsServer(source_p)) 
		return;

	if(parc < 3)
		return;

	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
		return;


	if(!MyClient(target_p))
		return;
	mo_saumode(client_p,source_p,parc,parv);
}

/*
 * mo_saumode
 *      parv[0] = sender prefix
 *      parv[1] = parameter
 */
static void
mo_saumode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	unsigned int flag, setflags;
	struct Client *target_p = (struct Client*)find_client(parv[1]);
	int what = MODE_ADD;
	int i;


	/* find flags already set for user */
	setflags = target_p->umodes;

	/* parse mode change string(s) */
	for(i = 0; i<strlen(parv[2]); i++)
	{
		switch (*(parv[2]+i))
		{
		case '+':
			what = MODE_ADD;
			break;

		case '-':
			what = MODE_DEL;
			break;

		case 'x':
			if(what == MODE_ADD)
			{
				char cloaked_host[HOSTLEN + 1] = "";

				if(IsCloaked(target_p))
					break;

				SetCloaked(target_p);

				if(!MyClient(target_p))
					break;

				make_virthost(target_p->realhost, cloaked_host);
				change_local_host(target_p, NULL, cloaked_host);

				sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
					      LL_ICLIENT, ":%s ENCAP * CHGHOST %s %s",
					      me.name, target_p->name, target_p->host);

				sendto_one(target_p, form_str(RPL_VISIBLEHOST), me.name,
					   target_p->name, target_p->host);
			}
			else
			{
				if(!IsCloaked(target_p))
					break;

				ClearCloaked(target_p);

				if(!MyClient(target_p))
					break;

				change_local_host(target_p, NULL, target_p->realhost);

				sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
					      LL_ICLIENT, ":%s ENCAP * CHGHOST %s %s",
					      me.name, target_p->name, target_p->host);

				sendto_one(target_p, form_str(RPL_VISIBLEHOST), me.name,
					   target_p->name, target_p->host);
			}
			break;

		case 'o':
			if(what == MODE_ADD)
			{
				mo_operup(target_p,parc - 3,parv + 3);
			}
			else
			{
				/* Only decrement the oper counts if an oper to begin with
				 * found by Pat Szuta, Perly , perly@xnet.com 
				 */
				if(!IsOper(target_p))
					break;

				ClearOper(target_p);
				target_p->umodes &= ~ConfigFileEntry.oper_only_umodes;

				/* remove their netadmin flag if set */
				if(IsNetAdmin(target_p))
					ClearNetAdmin(target_p);
				if(IsRouting(target_p))
					ClearRouting(target_p);

				Count.oper--;

				if(MyConnect(target_p))
				{
					dlink_node *dm;

					detach_conf(target_p, OPER_TYPE);
					ClearOperFlags(target_p);

					if((dm =
					    dlinkFindDelete(&oper_list, target_p)) != NULL)
						free_dlink_node(dm);
				}
			}
			break;

		case ' ':
		case '\n':
		case '\r':
		case '\t':
			break;

		default:
			if((flag = user_modes[(unsigned char) *(parv[2]+i)]))
			{
				if(what == MODE_ADD)
					target_p->umodes |= flag; 
				else
					target_p->umodes &= ~flag; 
			}
			break;
		}
	}

	if(!(setflags & UMODE_INVISIBLE) && IsInvisible(target_p))
		++Count.invisi;
	if((setflags & UMODE_INVISIBLE) && !IsInvisible(target_p))
		--Count.invisi;
	if(IsNetAdmin(target_p) && !IsRouting(target_p))
		target_p->umodes |= UMODE_ROUTING;

	/*
	 * compare new flags with old flags and send string which
	 * will cause servers to update correctly.
	 */
	if(setflags != target_p->umodes)
	{
		send_sumode_out(target_p, setflags); 
	}
}

unsigned int
oper_privs_as_int(unsigned int oldflags, char *oflags)
{		
	unsigned int port = oldflags;
	int what = MODE_ADD;
	int i;


	for(i = 0; i<strlen(oflags); i++)
	{
		switch(*(oflags+i)) { 
			case '+':
				what = MODE_ADD;
				break;
			case '-':
				what = MODE_DEL;
				break;
			case 'A':
				if(what == MODE_ADD)
					port |= OPER_FLAG_ADMIN;
				else
					port &= ~OPER_FLAG_ADMIN;
				break;
			case 'B':
				if(what == MODE_ADD)
					port |= OPER_FLAG_REMOTEBAN;
				else
					port &= ~OPER_FLAG_REMOTEBAN;
				break;
			case 'D':
				if(what == MODE_ADD)
					port |= OPER_FLAG_DIE;
				else
					port &= ~OPER_FLAG_DIE;
				break;
			case 'G':
				if(what == MODE_ADD)
					port |= OPER_FLAG_GLINE;
				else
					port &= ~OPER_FLAG_GLINE;
				break;
			case 'H':
				if(what == MODE_ADD)
					port |= OPER_FLAG_REHASH;
				else
					port &= ~OPER_FLAG_REHASH;
				break;
			case 'K':
				if(what == MODE_ADD)
					port |= OPER_FLAG_K;
				else
					port &= ~OPER_FLAG_K;
				break;
			case 'L':
				if(what == MODE_ADD)
					port |= OPER_FLAG_OPERWALL;
				else
					port &= ~OPER_FLAG_OPERWALL;
				break;
			case 'N':
				if(what == MODE_ADD)
					port |= OPER_FLAG_N;
				else
					port &= ~OPER_FLAG_N;
				break;
			case 'O':
				if(what == MODE_ADD)
					port |= OPER_FLAG_GLOBAL_KILL;
				else
					port &= ~OPER_FLAG_GLOBAL_KILL;
				break;
			case 'R':
				if(what == MODE_ADD)
					port |= OPER_FLAG_REMOTE;
				else
					port &= ~OPER_FLAG_REMOTE;
				break;
			case 'S':
				if(what == MODE_ADD)
					port |= OPER_FLAG_OPER_SPY;
				else
					port &= ~OPER_FLAG_OPER_SPY;
				break;
			case 'U':
				if(what == MODE_ADD)
					port |= OPER_FLAG_UNKLINE;
				else
					port &= ~OPER_FLAG_UNKLINE;
				break;
			case 'X':
				if(what == MODE_ADD)
					port |= OPER_FLAG_X;
				else
					port &= ~OPER_FLAG_X;
				break;
			case 'Z':
				if(what == MODE_ADD)
					port |= OPER_FLAG_HIDDEN_OPER;
				else
					port &= ~OPER_FLAG_HIDDEN_OPER;
				break;
			case 'a':
				if(what == MODE_ADD)
					port |= OPER_FLAG_HIDDEN_ADMIN;
				else
					port &= ~OPER_FLAG_HIDDEN_ADMIN;
				break;
			default:
				break;
    		}
	}
	return port;
}

static void
mo_operup(struct Client *source_p, int parc, char *parv[])
{
	unsigned int old = source_p->umodes;
	unsigned int operprivs = source_p->localClient->operflags;
	char *newoflags;

	if(!IsOper(source_p))
	{
		++Count.oper;
		SetOper(source_p);

		source_p->umodes |= (UMODE_SERVNOTICE | UMODE_OPERWALL |
				     UMODE_WALLOP | UMODE_LOCOPS);

		assert(dlinkFind(&oper_list, source_p) == NULL);
		dlinkAdd(source_p, make_dlink_node(), &oper_list);
	}

	if(parc > 0)
	{
		operprivs = oper_privs_as_int(operprivs, parv[0]);
		ClearOperFlags(source_p);
		SetOFlag(source_p, operprivs);
	}

	if(IsOperAdmin(source_p) || IsOperHiddenAdmin(source_p))
		source_p->umodes |= UMODE_ADMIN;
	else
		source_p->umodes &= ~UMODE_ADMIN;
	if(!IsOperN(source_p))
		source_p->umodes &= ~UMODE_NCHANGE;

	sendto_realops_flags(UMODE_ALL, L_ALL, "%s (%s@%s) is now an operator",
			     source_p->name, source_p->username, source_p->realhost);
	send_umode_out(source_p, source_p, old);
	sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
	newoflags = oper_privs_as_string(operprivs);
	sendto_one(source_p, ":%s NOTICE %s :*** Oper privs are %s",
		   me.name, source_p->name, (*newoflags != '\0') ? newoflags : "[none]");
	send_message_file(source_p, &ConfigFileEntry.opermotd);
} 

static void 
ms_smode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	unsigned int flag, setflags;
	char **p, *m;
	struct Client *target_p;
	int what = MODE_ADD;

	if((parc < 3) || (*parv[1] == '\0'))
	{
		return;
	}

	/* Now, try to find the channel in question */
	if(IsChanPrefix(*parv[1]))
	{
		return;
	}
	
	if((target_p = find_person(client_p, parv[1])) == NULL)
	{
		return;
	}
	
	if(!IsServer(source_p))
	{
		return;
	} 

	if(target_p->from != source_p)
	{
		return;
	} 

	/* find flags already set for user */
	setflags = target_p->umodes;

	/* parse mode change string(s) */
	for(p = &parv[2]; p && *p; p++)
	{
		for(m = *p; *m; m++)
		{
			switch (*m)
			{
			case '+':
				what = MODE_ADD;
				break;
			case '-':
				what = MODE_DEL;
				break;

			case 'x':
				if(what == MODE_ADD)
				{
					int localclient = MyClient(target_p);
					char cloaked_host[HOSTLEN + 1] = "";

					if(localclient)
						if(!ConfigFileEntry.enable_cloak_system ||
						   IsIPSpoof(target_p))
							break;

					if(IsCloaked(target_p))
						break;

					SetCloaked(target_p);

					if(!localclient)
						break;

					make_virthost(target_p->realhost, cloaked_host);
					change_local_host(target_p, NULL, cloaked_host);

					sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
						      LL_ICLIENT, ":%s ENCAP * CHGHOST %s %s",
						      me.name, target_p->name, target_p->host);

					sendto_one(target_p, form_str(RPL_VISIBLEHOST), me.name,
						   target_p->name, target_p->host);
				}
				else
				{
					if(!IsCloaked(target_p))
						break;

					ClearCloaked(target_p);

					if(!MyClient(target_p))
						break;

					change_local_host(target_p, NULL, target_p->realhost);

					sendto_server(NULL, target_p, NULL, CAP_ENCAP, NOCAPS,
						      LL_ICLIENT, ":%s ENCAP * CHGHOST %s %s",
						      me.name, target_p->name, target_p->host);

					sendto_one(target_p, form_str(RPL_VISIBLEHOST), me.name,
						   target_p->name, target_p->host);
				}
				break;

			case 'o':
				if(what == MODE_ADD)
				{
					if(IsServer(client_p) && !IsOper(target_p))
					{
						++Count.oper;
						SetOper(target_p);
					}
				}
				else
				{
					/* Only decrement the oper counts if an oper to begin with
					 * found by Pat Szuta, Perly , perly@xnet.com 
					 */
					if(!IsOper(target_p))
						break;

					ClearOper(target_p);
					target_p->umodes &= ~ConfigFileEntry.oper_only_umodes;

					/* remove their netadmin flag if set */
					if(IsNetAdmin(target_p))
						ClearNetAdmin(target_p);
					if(IsRouting(target_p))
						ClearRouting(target_p);

					Count.oper--;

					if(MyConnect(target_p))
					{
						dlink_node *dm;

						detach_conf(target_p, OPER_TYPE);
						ClearOperFlags(target_p);

						if((dm =
						    dlinkFindDelete(&oper_list, target_p)) != NULL)
							free_dlink_node(dm);
					}
				}

				break;

				/* we may not get these,
				 * but they shouldnt be in default
				 */
			case ' ':
			case '\n':
			case '\r':
			case '\t':
				break;

			default:
				if((flag = user_modes[(unsigned char) *m]))
				{
					if(what == MODE_ADD)
						target_p->umodes |= flag;
					else
						target_p->umodes &= ~flag;
				}
				break;
			}
		}
	}

	if(!(setflags & UMODE_INVISIBLE) && IsInvisible(target_p))
		++Count.invisi;
	if((setflags & UMODE_INVISIBLE) && !IsInvisible(target_p))
		--Count.invisi;
	if(IsNetAdmin(target_p) && !IsRouting(target_p))
		target_p->umodes |= UMODE_ROUTING;
	/*
	 * compare new flags with old flags and send string which
	 * will cause servers to update correctly.
	 */
	send_sumode_out(target_p, setflags);
}

/* do_join_0()
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
	struct Channel *chptr = NULL;
	dlink_node *ptr = NULL, *ptr_next = NULL;

	DLINK_FOREACH_SAFE(ptr, ptr_next, source_p->channel.head)
	{
		chptr = ((struct Membership *) ptr->data)->chptr;

		sendto_server(client_p, NULL, chptr, CAP_TS6, NOCAPS, NOFLAGS,
			      ":%s PART %s", ID(source_p), chptr->chname);
		sendto_server(client_p, NULL, chptr, NOCAPS, CAP_TS6, NOFLAGS,
			      ":%s PART %s", source_p->name, chptr->chname);
		sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s PART %s",
				     source_p->name, source_p->username,
				     source_p->host, chptr->chname);

		remove_user_from_channel(ptr->data);
	}
} 

/* last0() stolen from ircu */
static char *
last0(struct Client *client_p, struct Client *source_p, char *chanlist)
{
	char *p;
	int join0 = 0;

	for(p = chanlist; *p; ++p)	/* find last "JOIN 0" */
	{
		if(*p == '0' && (*(p + 1) == ',' || *(p + 1) == '\0'))
		{
			if((*p + 1) == ',')
				++p;

			chanlist = p + 1;
			join0 = 1;
		}
		else
		{
			while(*p != ',' && *p != '\0')	/* skip past channel name */
				++p;

			if(*p == '\0')	/* hit the end */
				break;
		}
	}

	if(join0)
		do_join_0(client_p, source_p);

	return chanlist;
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

	char rname[IRCD_BUFSIZE];
	char ruser[IRCD_BUFSIZE];
	char rhost[IRCD_BUFSIZE];
	char rbuff[IRCD_BUFSIZE];
	char errbuff[IRCD_BUFSIZE];
	struct split_nuh_item rnuh;
	pcre *exp_nick = NULL, *exp_user = NULL, *exp_host = NULL;
	const char *errptr = NULL; 
	int hosttype = HM_HOST;
	struct irc_ssaddr raddr;
	int rbits; 
	char *s; 

							
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
				   me.name, source_p->name, "SAMODE", "Channel modes string too long");
			return -1;
		}
		if(is_rban > 1)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "SAMODE", "You can use only one regex ban per line");
			return -1;
		}
		if(has_param_mode > 1)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "SAMODE", "You cannot use other parametric modes with regex ban");
			return -1;
		}
		if(strlen(parv[rban_index]) > 200)
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "SAMODE", "Regex too long");
			return -1;
		}
	
		if(!match("r/*", parv[rban_index]))	
		{
			sendto_one(source_p, form_str(ERR_CANNOTDOCOMMAND),
				   me.name, source_p->name, "SAMODE", "Missing regex prefix");
			return -1;
		}

		ircsprintf(rbuff, "%s", parv[rban_index]);
		rnuh.nuhmask = rbuff;
		rnuh.nickptr = rname;
		rnuh.userptr = ruser;
		rnuh.hostptr = rhost;

		rnuh.nicksize = sizeof(rname);
		rnuh.usersize = sizeof(ruser);
		rnuh.hostsize = sizeof(rhost);
		
		split_nuh(&rnuh);
	
		s = strchr(rname, '/');
		s++; 

		if((exp_nick = ircd_pcre_compile(s, &errptr)) && 
		   (exp_user = ircd_pcre_compile(ruser, &errptr)))
		{
			hosttype = parse_netmask(rhost, &raddr, &rbits);
			if(hosttype == HM_HOST)
			{
				exp_host = ircd_pcre_compile(rhost, &errptr);
				if(!exp_host)
				{
					ircsprintf(errbuff, "Incorrect regex syntax: %s", errptr);
					sendto_one(client_p, form_str(ERR_CANNOTDOCOMMAND),
						   me.name, client_p->name, "SAMODE", errbuff);
					return -1;
				}
			}
		}
		else
		{
			ircsprintf(errbuff, "Incorrect regex syntax: %s", errptr);
			sendto_one(client_p, form_str(ERR_CANNOTDOCOMMAND),
			   me.name, client_p->name, "SAMODE", errbuff);
			return -1;
 		}
	
		return 1;
	}
	return 0;
}

void
send_sumode_out(struct Client *source_p, unsigned int old)
{
	char buf[IRCD_BUFSIZE] = { '\0' };
	dlink_node *ptr = NULL;

	send_umode(NULL, source_p, old, IsOperHiddenAdmin(source_p) ?
		   SEND_UMODES & ~UMODE_ADMIN : SEND_UMODES, buf);

	if(buf[0])
	{
		DLINK_FOREACH(ptr, serv_list.head)
		{
			struct Client *targetsrv_p = ptr->data;

			if((targetsrv_p != source_p) && (targetsrv_p != source_p->servptr))
			{
				if((!(ServerInfo.hub && IsCapable(targetsrv_p, CAP_LL))) ||
				   (targetsrv_p->localClient->serverMask &
				    source_p->lazyLinkClientExists))
					sendto_one(targetsrv_p, ":%s SMODE %s :%s",
						   ID_or_name(source_p->servptr, targetsrv_p),
						   ID_or_name(source_p, targetsrv_p), buf);
			}
		}
	}

	if(source_p && MyClient(source_p))
		send_umode(source_p, source_p, old, 0xffffffff, buf);
}
