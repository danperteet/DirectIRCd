/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_services.c: SVS commands and Services support
 *
 *  Copyright (C) 2005 by the past and present ircd coders, and others.
 *  Portions Copyright (C) 2004 The bahamut team
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
 *  $Id: m_services.c 493 2007-07-07 17:45:14Z jon $
 */
/*
 *
 * With code from 'bane' the URL following is valid as of this date.
 * http://hybserv2.net/file/trunk/contrib/hybrid_services.c
 *
 *
 *   Copyright (C) 2002, 2003, 2004, 2005 by Dragan 'bane' Dosen and the
 *   Hybrid Development Team.
 *
 *   Based on m_services.c, originally from bahamut ircd.
 *
 *   Contact info:
 *
 *     E-mail : bane@idolnet.org
 *     IRC    : (*) bane, idolNET, irc.idolnet.org, #twilight_zone
 */
#include "stdinc.h"
#include "handlers.h"
#include "client.h"
#include "hash.h"
#include "fdlist.h"
#include "irc_string.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_stats.h"
#include "s_user.h"
#include "whowas.h"
#include "s_serv.h"
#include "send.h"
#include "list.h"
#include "channel.h"
#include "channel_mode.h"
#include "s_log.h"
#include "resv.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "common.h"
#include "packet.h"
#include "sprintf_irc.h"
#include "cloak.h"

/* Custom Macros */
#define services_function(a,b,c) static void a(struct Client *client_p,\
        struct Client *source_p, int parc,\
        char *parv[]) \
{ deliver_services_msg(b, c, client_p, source_p, parc, parv); }

static void me_svsjoin(struct Client *, struct Client *, int, char *[]);
static void me_svsmode(struct Client *, struct Client *, int, char *[]);
static void me_svsnick(struct Client *, struct Client *, int, char *[]);
static void me_svsnoop(struct Client *, struct Client *, int, char *[]);
static void me_svspart(struct Client *, struct Client *, int, char *[]);

static void m_botserv(struct Client *, struct Client *, int, char *[]);
static void m_chanserv(struct Client *, struct Client *, int, char *[]);
static void m_hostserv(struct Client *, struct Client *, int, char *[]);
static void m_identify(struct Client *, struct Client *, int, char *[]);
static void m_memoserv(struct Client *, struct Client *, int, char *[]);
static void m_nickserv(struct Client *, struct Client *, int, char *[]);
static void m_operserv(struct Client *, struct Client *, int, char *[]);

static void get_string(int, char *[], char *);
static int clean_nick_name(char *, int, int);
static void deliver_services_msg(const char *, const char *, struct Client *,
				 struct Client *, int, char *[]);
				 
static void me_su(struct Client *, struct Client *, int, char *[]);
static void me_svskill(struct Client *, struct Client *, int, char *[]);

/* SVS commands */
struct Message svsjoin_msgtab = {
	"SVSJOIN", 0, 0, 3, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svsjoin, m_ignore, m_ignore}
};

struct Message svsmode_msgtab = {
	"SVSMODE", 0, 0, 4, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svsmode, m_ignore, m_ignore}
};

struct Message svsnick_msgtab = {
	"SVSNICK", 0, 0, 5, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svsnick, m_ignore, m_ignore}
};

struct Message svsnoop_msgtab = {
	"SVSNOOP", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svsnoop, m_ignore, m_ignore}
};

struct Message svspart_msgtab = {
	"SVSPART", 0, 0, 3, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svspart, m_ignore, m_ignore}
};

struct Message su_msgtab = {
	"SU", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_su, m_ignore, m_ignore}
};

struct Message svskill_msgtab = {
	"SVSKILL", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_svskill, m_ignore, m_ignore}
};

/* Services */
struct Message botserv_msgtab = {
	"BOTSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_botserv, m_ignore, m_ignore, m_botserv, m_ignore}
};

struct Message bs_msgtab = {
	"BS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_botserv, m_ignore, m_ignore, m_botserv, m_ignore}
};

struct Message chanserv_msgtab = {
	"CHANSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_chanserv, m_ignore, m_ignore, m_chanserv, m_ignore}
};

struct Message cs_msgtab = {
	"CS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_chanserv, m_ignore, m_ignore, m_chanserv, m_ignore}
};

struct Message hostserv_msgtab = {
	"HOSTSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_hostserv, m_ignore, m_ignore, m_hostserv, m_ignore}
};

struct Message hs_msgtab = {
	"HS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_hostserv, m_ignore, m_ignore, m_hostserv, m_ignore}
};

struct Message memoserv_msgtab = {
	"MEMOSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_memoserv, m_ignore, m_ignore, m_memoserv, m_ignore}
};

struct Message ms_msgtab = {
	"MS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_memoserv, m_ignore, m_ignore, m_memoserv, m_ignore}
};

struct Message nickserv_msgtab = {
	"NICKSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_nickserv, m_ignore, m_ignore, m_nickserv, m_ignore}
};

struct Message ns_msgtab = {
	"NS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_nickserv, m_ignore, m_ignore, m_nickserv, m_ignore}
};

struct Message operserv_msgtab = {
	"OPERSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_operserv, m_ignore, m_ignore, m_operserv, m_ignore}
};

struct Message os_msgtab = {
	"OS", 0, 0, 1, 0, MFLG_SLOW, 0,
	{m_unregistered, m_operserv, m_ignore, m_ignore, m_operserv, m_ignore}
};

struct Message identify_msgtab = {
	"IDENTIFY", 0, 0, 0, 2, MFLG_SLOW, 0,
	{m_unregistered, m_identify, m_ignore, m_ignore, m_identify, m_ignore}
};

#ifndef STATIC_MODULES
void
_modinit(void)
{
	mod_add_cmd(&svsjoin_msgtab);
	mod_add_cmd(&svsmode_msgtab);
	mod_add_cmd(&svsnick_msgtab);
	mod_add_cmd(&svsnoop_msgtab);
	mod_add_cmd(&svspart_msgtab);
	mod_add_cmd(&su_msgtab);
	mod_add_cmd(&svskill_msgtab);
	mod_add_cmd(&botserv_msgtab);
	mod_add_cmd(&bs_msgtab);
	mod_add_cmd(&chanserv_msgtab);
	mod_add_cmd(&cs_msgtab);
	mod_add_cmd(&hostserv_msgtab);
	mod_add_cmd(&hs_msgtab);
	mod_add_cmd(&memoserv_msgtab);
	mod_add_cmd(&ms_msgtab);
	mod_add_cmd(&nickserv_msgtab);
	mod_add_cmd(&ns_msgtab);
	mod_add_cmd(&operserv_msgtab);
	mod_add_cmd(&os_msgtab);
	mod_add_cmd(&identify_msgtab);
	add_isupport("FNC", NULL, -1);
	add_capability("SVS", CAP_SVS, 0);
}

void
_moddeinit(void)
{
	mod_del_cmd(&svsjoin_msgtab);
	mod_del_cmd(&svsmode_msgtab);
	mod_del_cmd(&svsnick_msgtab);
	mod_del_cmd(&svsnoop_msgtab);
	mod_del_cmd(&svspart_msgtab);
	mod_del_cmd(&su_msgtab);
	mod_del_cmd(&svskill_msgtab);
	mod_del_cmd(&botserv_msgtab);
	mod_del_cmd(&bs_msgtab);
	mod_del_cmd(&chanserv_msgtab);
	mod_del_cmd(&cs_msgtab);
	mod_del_cmd(&hostserv_msgtab);
	mod_del_cmd(&hs_msgtab);
	mod_del_cmd(&memoserv_msgtab);
	mod_del_cmd(&ms_msgtab);
	mod_del_cmd(&nickserv_msgtab);
	mod_del_cmd(&ns_msgtab);
	mod_del_cmd(&operserv_msgtab);
	mod_del_cmd(&os_msgtab);
	mod_del_cmd(&identify_msgtab);
	delete_isupport("FNC");
	delete_capability("SVS");
}

const char *_version = "$Revision: 493 $";
#endif

/* Code provided by orabidoo
 *
 * a random number generator loosely based on RC5; assumes ints are at
 * least 32 bit
 */
static unsigned long
my_rand()
{
	static unsigned long s = 0, t = 0, k = 12345678;
	int i;

	if(s == 0 && t == 0)
	{
		s = (unsigned long) getpid();
		t = (unsigned long) time(NULL);
	}
	for(i = 0; i < 12; i++)
	{
		s = (((s ^ t) << (t & 31)) | ((s ^ t) >> (31 - (t & 31)))) + k;
		k += s + t;
		t = (((t ^ s) << (s & 31)) | ((t ^ s) >> (31 - (s & 31)))) + k;
		k += s + t;
	}
	return s;
}

/* me_svsmode
 *
 * parv[0] - sender
 * parv[1] - nick
 * parv[2] - TS
 * parv[3] - mode
 * parv[4] - optional arguement (services id)
 */
static void
me_svsmode(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	unsigned int flag, setflags;
	char **p, *m, *optarg;
	struct Client *target_p;
	int what = MODE_ADD;
	time_t ts = 0;

	if(!IsServices(source_p) || (parc < 4))
		return;

	if((target_p = find_person(client_p, parv[1])) == NULL)
		return;

	ts = atol(parv[2]);
	optarg = (parc > 4) ? parv[4] : NULL;

	if(ts && (ts != target_p->tsinfo))
		return;

	/* find flags already set for user */
	setflags = target_p->umodes;

	/* parse mode change string(s) */
	for(p = &parv[3]; p && *p; p++)
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

			case 'd':
				if(optarg && IsDigit(*optarg))
					target_p->servicestamp = strtoul(optarg, NULL, 0);
				break;

			case 'o':
				if(what == MODE_ADD)
					/* Do not allow opering via SVSMODE */
					break;
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

			case 'x':
				if(what == MODE_ADD)
				{
					/* when setting +x via SVSMODE do not call the cloaking system. */
					if(IsCloaked(target_p))
						break;

					SetCloaked(target_p);
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

					sendto_one(target_p, form_str(RPL_VISIBLEHOST),
						   me.name, target_p->name, target_p->host);
				}
				break;

				/* Do not allow SVSMODE to set/unset umode S */
			case 'S':
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
					if(MyConnect(target_p) && !IsOper(target_p)
					   && (ConfigFileEntry.oper_only_umodes & flag))
						break;

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
		
	if(MyClient(target_p) && (setflags != target_p->umodes))
	{
		char buf[IRCD_BUFSIZE];
		send_umode(target_p, target_p, setflags, 0xffffffff, buf);
	}
}

/*
 * me_svsnick()
 *
 * parv[0] = sender
 * parv[1] = nick
 * parv[2] = TS
 * parv[3] = new nick
 * parv[4] = new TS
 */
static void
me_svsnick(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	char nick[NICKLEN];
	struct Client *target_p = NULL;
	struct Client *exists_p = NULL;
	time_t newts = 0;
	time_t curts = 0;

	if(!IsServices(source_p) || EmptyString(parv[3]))
		return;

	if((target_p = find_person(client_p, parv[1])) == NULL)
		return;

	if(!MyClient(target_p))
		return;

	curts = atol(parv[2]);

	if(curts && (curts != target_p->tsinfo))
		return;

	/* terminate nick to NICKLEN */
	strlcpy(nick, parv[3], sizeof(nick));

	if(!clean_nick_name(nick, 1, IsNetAdmin(target_p)))
		return;

	if((exists_p = find_client(nick)) != NULL)
	{
		int tries = 0, nprefix;

		if(target_p == exists_p)
			return;

		do
		{
			nprefix = my_rand() % 99999;
			snprintf(nick, sizeof(nick), "%s-%d", parv[3], nprefix);
			tries++;
		}
		while(((exists_p = find_client(nick)) != NULL) && (tries < 10));

		if(exists_p)
		{
			if(IsUnknown(exists_p))
			{
				exit_client(exists_p, &me, "SVSNICK Override");
				return;
			}
			else
			{
				exit_client(target_p, &me, "SVSNICK Collide");
				return;
			}
		}
	}

	newts = atol(parv[4]);

	/* timestamp is older than 15mins, ignore it */
	if(newts < (CurrentTime - 900))
		newts = CurrentTime - 900;

	/*
	 * Make sure everyone that has this client on its accept list
	 * loses that reference.
	 */
	del_all_their_accepts(target_p);
	target_p->localClient->last_nick_change = newts;
	target_p->tsinfo = newts;
	clear_ban_cache_client(target_p);

	/* If it changed nicks, -r it */
	if(IsRegNick(target_p))
	{
		unsigned int oldumodes;
		char umodebuf[IRCD_BUFSIZE];

		oldumodes = target_p->umodes;
		ClearRegNick(target_p);
		send_umode(target_p, target_p, oldumodes, 0xffffffff, umodebuf);
	}

	/* 
	 * XXX - the format of this notice should eventually be changed
	 * to either %s[%s@%s], or even better would be get_client_name() -bill
	 */
	sendto_realops_flags(UMODE_NCHANGE, L_ALL, "Nick change: From %s to %s [%s@%s]",
			     target_p->name, nick, target_p->username, target_p->realhost);
	sendto_common_channels_local(target_p, 1, ":%s!%s@%s NICK :%s",
				     target_p->name, target_p->username, target_p->host, nick);
	add_history(target_p, 1);

	/* 
	 * Only hubs care about lazy link nicks not being sent on yet
	 * lazylink leafs/leafs always send their nicks up to hub,
	 * hence must always propagate nick changes.
	 * hubs might not propagate a nick change, if the leaf
	 * does not know about that client yet.
	 */
	sendto_server(NULL, target_p, NULL, CAP_TS6, NOCAPS, NOFLAGS,
		      ":%s NICK %s :%lu", ID(target_p), nick, (unsigned long) target_p->tsinfo);
	sendto_server(NULL, target_p, NULL, NOCAPS, CAP_TS6, NOFLAGS,
		      ":%s NICK %s :%lu", target_p->name, nick, (unsigned long) target_p->tsinfo);

	/* Finally, add to hash */
	if(target_p->name[0])
		hash_del_client(target_p);

	strcpy(target_p->name, nick);
	hash_add_client(target_p);

	/* fd_desc is long enough */
	fd_note(&target_p->localClient->fd, "Nick: %s", nick);
}

/*
 * me_svsnoop()
 *
 * parv[0] = sender
 * parv[1] = + if being set, - if being unset.
 */
static void
me_svsnoop(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	dlink_node *ptr, *next_ptr;
	unsigned int setflags;

	if(!IsServices(source_p) || EmptyString(parv[1]))
		return;

	if(parv[1][0] == '+')
	{
		svsnoop = 1;
		sendto_realops_flags(UMODE_ALL, L_ALL, "This server has been placed in NOOP mode");

		DLINK_FOREACH_SAFE(ptr, next_ptr, oper_list.head)
		{
			dlink_node *dm;
			target_p = ptr->data;

			if(!MyClient(target_p) || !IsOper(target_p))
				continue;

			/* find flags already set for user */
			setflags = target_p->umodes;

			ClearOper(target_p);
			target_p->umodes &= ~ConfigFileEntry.oper_only_umodes;

			/* remove their netadmin flag if set */
			if(IsNetAdmin(target_p))
				ClearNetAdmin(target_p);
			if(IsRouting(target_p))
				ClearRouting(target_p);

			Count.oper--;
			detach_conf(target_p, OPER_TYPE);
			ClearOperFlags(target_p);

			if((dm = dlinkFindDelete(&oper_list, target_p)) != NULL)
				free_dlink_node(dm);

			send_umode_out(target_p, target_p, setflags);
		}
	}
	else
	{
		svsnoop = 0;
		sendto_realops_flags(UMODE_ALL, L_ALL, "This server is no longer in NOOP mode");
	}
}

/*
 * These generate the services functions through
 * a macro.
 */
services_function(m_botserv, "BotServ", "BOTSERV")
services_function(m_chanserv, "ChanServ", "CHANSERV")
services_function(m_hostserv, "HostServ", "HOSTSERV")
services_function(m_memoserv, "MemoServ", "MEMOSERV")
services_function(m_nickserv, "NickServ", "NICKSERV")
services_function(m_operserv, "OperServ", "OPERSERV")
/*
 * get_string() 
 *
 * Reverse the array parv back into a normal string assuming
 * there are "parc" indicies in the array.
 *
 * Originally GetString() written by sidewndr.
 * Modified by Michael for use with hybrid-7.
 */
     static void get_string(int parc, char *parv[], char *buf)
{
	int ii = 0;
	int bw = 0;

	for(; ii < parc; ++ii)
		bw += ircsprintf(buf + bw, "%s ", parv[ii]);
	buf[bw - 1] = '\0';
}

/*
 * clean_nick_name()
 *
 * input        - nickname
 * output       - none
 * side effects - walks through the nickname, returning 0 if erroneous
 */
static int
clean_nick_name(char *nick, int local, int netadmin)
{
	assert(nick);

	/* nicks can't start with a digit or - or be 0 length */
	/* This closer duplicates behaviour of hybrid-6 */

	if(*nick == '-' || (IsDigit(*nick) && local) || *nick == '\0')
		return 0;

	for(; *nick; ++nick)
	{
		if((unsigned char)(*nick) == 0xA0)
			continue;
		if(!IsNickChar(*nick))
			return 0;
	}

	return 1;
}

/*
 * m_identify()
 *
 * parv[0] = sender prefix
 * parv[1] = NickServ Password or Channel
 * parv[2] = ChanServ Password
 */
static void
m_identify(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	switch (parc)
	{
	case 2:
		if(!(target_p = find_server(ConfigFileEntry.services_name)))
			sendto_one(source_p, form_str(ERR_SERVICESDOWN), me.name, source_p->name,
				   "NickServ");
		else
			sendto_one(target_p, ":%s PRIVMSG NickServ@%s :IDENTIFY %s",
				   source_p->name, ConfigFileEntry.services_name, parv[1]);
		break;

	case 3:
		if(!(target_p = find_server(ConfigFileEntry.services_name)))
			sendto_one(source_p, form_str(ERR_SERVICESDOWN), me.name, source_p->name,
				   "ChanServ");
		else
			sendto_one(target_p, ":%s PRIVMSG ChanServ@%s :IDENTIFY %s %s",
				   source_p->name, ConfigFileEntry.services_name, parv[1], parv[2]);
		break;

	default:
		sendto_one(source_p, ":%s NOTICE %s :Syntax: IDENTIFY <password> "
			   "- for nickname", me.name, source_p->name);
		sendto_one(source_p, ":%s NOTICE %s :Syntax: IDENTIFY <channel> "
			   "<password> - for channel", me.name, source_p->name);
		break;
	}
}

/*
 * deliver_services_msg()
 *
 * parv[0] = sender prefix
 * servmsg = message for services (utilising GetString())
 *
 * Borrowed from HybServ -- knight-
 */
static void
deliver_services_msg(const char *service, const char *command,
		     struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	char buf[IRCD_BUFSIZE] = { '\0' };

	if(parc < 2 || *parv[1] == '\0')
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name, source_p->name, command);
		return;
	}

	if(!(target_p = find_server(ConfigFileEntry.services_name)))
		sendto_one(source_p, form_str(ERR_SERVICESDOWN), me.name, source_p->name, service);
	else
	{
		get_string(parc - 1, parv + 1, buf);
		sendto_one(target_p, ":%s PRIVMSG %s@%s :%s",
			   source_p->name, service, ConfigFileEntry.services_name, buf);
	}
}

/* me_svsjoin()
 *
 * parv[0] = sender prefix
 * parv[1] = target
 * parv[2] = channel to join
 */
static void
me_svsjoin(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	struct Channel *chptr = NULL;
	unsigned int type = 0;
	char mode = '\0';
	char sjmode = '\0';
	char *newch = NULL;

	if(!IsServices(source_p))
		return;

	if((target_p = find_client(parv[1])) == NULL)
		return;

	if(!MyClient(target_p))
		return;

	/* select our modes from parv[2] if they exist... (chanop) */
	switch (*parv[2])
	{
#ifdef CHANAQ
	case '~':
		type = CHFL_OWNER;
		mode = 'q';
		sjmode = '~';
		parv[2]++;
		break;
	case '&':
		type = CHFL_PROTECTED;
		mode = 'a';
		sjmode = '&';
		parv[2]++;
		break;
#endif
	case '@':
		type = CHFL_CHANOP;
		mode = 'o';
		sjmode = '@';
		parv[2]++;
		break;
#ifdef HALFOPS
	case '%':
		type = CHFL_HALFOP;
		mode = 'h';
		sjmode = '%';
		parv[2]++;
		break;
#endif
	case '+':
		type = CHFL_VOICE;
		mode = 'v';
		sjmode = '+';
		parv[2]++;
		break;
	default:
		type = 0;
		mode = sjmode = '\0';	/* make sure sjmode is 0. sjoin depends on it */
		break;
	}

	if((chptr = hash_find_channel(parv[2])) != NULL)
	{
		if(IsMember(target_p, chptr))
			return;

		add_user_to_channel(chptr, target_p, type, NO);

		sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s JOIN :%s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname);

		if(sjmode)
			sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s MODE %s +%c %s",
					     me.name, chptr->chname, mode, target_p->name);

		if(chptr->chname[0] == '#')
		{
			if(sjmode)
			{
				sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%c%s", me.id,
					      (unsigned long) chptr->channelts, chptr->chname,
					      sjmode, target_p->id);
				sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%c%s", me.name,
					      (unsigned long) chptr->channelts, chptr->chname,
					      sjmode, target_p->name);
			}
			else
			{
				sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%s", me.id,
					      (unsigned long) chptr->channelts, chptr->chname,
					      target_p->id);
				sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6,
					      LL_ICLIENT, ":%s SJOIN %lu %s + :%s", me.name,
					      (unsigned long) chptr->channelts, chptr->chname,
					      target_p->name);
			}
		}

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
	else
	{
		newch = parv[2];

		if(!check_channel_name(newch, 1))
			return;

		/* 
		 * it would be interesting here to allow an oper
		 * to force target_p into a channel that doesn't exist
		 * even more so, into a local channel when we disable
		 * local channels... but...
		 * I don't want to break anything - scuzzy
		 */
		if(ConfigChannel.disable_local_channels && (*newch == '&'))
			return;

		chptr = make_channel(newch);
		add_user_to_channel(chptr, target_p, CHFL_CHANOP, NO);

		/* send out a join, make target_p join chptr */
		if(chptr->chname[0] == '#')
		{
			sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS, LL_ICLIENT,
				      ":%s SJOIN %lu %s +nt :@%s",
				      me.id, (unsigned long) chptr->channelts,
				      chptr->chname, ID(target_p));
			sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6, LL_ICLIENT,
				      ":%s SJOIN %lu %s +nt :@%s",
				      me.name, (unsigned long) chptr->channelts,
				      chptr->chname, target_p->name);
		}

		sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s JOIN :%s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname);

		chptr->mode.mode |= MODE_TOPICLIMIT | MODE_NOPRIVMSGS;

		sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s MODE %s +nt",
				     me.name, chptr->chname);

		target_p->localClient->last_join_time = CurrentTime;
		channel_member_names(target_p, chptr, 1);
	}
}

/* me_svspart()
 *
 * parv[0] = sender prefix
 * parv[1] = target
 * parv[2] = channel to part
 */
static void
me_svspart(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	struct Channel *chptr = NULL;
	struct Membership *member = NULL;

	if(!IsServices(source_p))
		return;

	if((target_p = find_client(parv[1])) == NULL)
		return;

	if(!MyClient(target_p))
		return;

	if((chptr = hash_find_channel(parv[2])) == NULL)
		return;

	if((member = find_channel_link(target_p, chptr)) == NULL)
		return;

	if(chptr->chname[0] == '#')
	{
		sendto_server(target_p, target_p, chptr, CAP_TS6, NOCAPS, LL_ICLIENT,
			      ":%s PART %s", ID(target_p), chptr->chname);
		sendto_server(target_p, target_p, chptr, NOCAPS, CAP_TS6, LL_ICLIENT,
			      ":%s PART %s", target_p->name, chptr->chname);
	}

	sendto_channel_local(ALL_MEMBERS, NO, chptr, ":%s!%s@%s PART %s",
			     target_p->name, target_p->username, target_p->host, chptr->chname);
	remove_user_from_channel(member);
}

/*
 * me_su
 *      parv[0] = sender prefix
 *      parv[1] = nick
 *      parv[2] = nick core identified to
 */
static void
me_su(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsServer(source_p) || !IsServices(source_p)) 
		return;

	if(parc < 2)
		return;

	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
		return;


	if(!IsClient(target_p))
		return;

	if(EmptyString(parv[2]))
		target_p->suser[0] = '\0';
	else
		strlcpy(target_p->suser, parv[2], sizeof(target_p->suser));
}

/*
 * me_svskill
 *      parv[0] = sender prefix
 *      parv[1] = nick to kill
 */
static void
me_svskill(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsServer(source_p) || !IsServices(source_p)) 
		return;

	if(parc < 2)
		return;

	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
		return;


	if(!IsClient(target_p))
		return;

	exit_client(target_p, &me, "SVSKILLED");
}
