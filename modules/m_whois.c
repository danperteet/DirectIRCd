/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  m_whois.c: Shows who a user is.
 *
 *  Copyright (C) 2005 by the past and present ircd coders, and others.
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
 *  $Id: m_whois.c 493 2007-07-07 17:45:14Z jon $
 */

#include "stdinc.h"
#include "fdlist.h"
#include "tools.h"
#include "common.h"
#include "handlers.h"
#include "client.h"
#include "hash.h"
#include "channel.h"
#include "channel_mode.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "list.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "hook.h"

static void do_whois(struct Client *, int, char **);
static int single_whois(struct Client *, struct Client *);
static void whois_person(struct Client *, struct Client *);
static int global_whois(struct Client *, const char *);

static void m_whois(struct Client *, struct Client *, int, char *[]);
static void mo_whois(struct Client *, struct Client *, int, char *[]);

struct Message whois_msgtab = {
	"WHOIS", 0, 0, 0, 0, MFLG_SLOW, 0,
	{m_unregistered, m_whois, mo_whois, m_ignore, mo_whois, m_ignore}
};

#ifndef STATIC_MODULES
const char *_version = "$Revision: 493 $";
static struct Callback *whois_cb;

static void *
va_whois(va_list args)
{
	struct Client *source_p = va_arg(args, struct Client *);
	int parc = va_arg(args, int);
	char **parv = va_arg(args, char **);

	do_whois(source_p, parc, parv);
	return NULL;
}

void
_modinit(void)
{
	whois_cb = register_callback("doing_whois", va_whois);
	mod_add_cmd(&whois_msgtab);
}

void
_moddeinit(void)
{
	mod_del_cmd(&whois_msgtab);
	uninstall_hook(whois_cb, va_whois);
}
#endif

/*
** m_whois
**      parv[0] = sender prefix
**      parv[1] = nickname masklist
*/
static void
m_whois(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	static time_t last_used = 0;

	if(parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN), me.name, source_p->name);
		return;
	}

	if(parc > 2 && !EmptyString(parv[2]))
	{
		/* seeing as this is going across servers, we should limit it */
		if((last_used + ConfigFileEntry.pace_wait_simple) > CurrentTime)
		{
			sendto_one(source_p, form_str(RPL_LOAD2HI), me.name, source_p->name);
			return;
		}
		else
			last_used = CurrentTime;

		/* if we have serverhide enabled, they can either ask the clients
		 * server, or our server.. I dont see why they would need to ask
		 * anything else for info about the client.. --fl_
		 */
		if(ConfigFileEntry.disable_remote)
			parv[1] = parv[2];

		if(hunt_server(client_p, source_p, ":%s WHOIS %s :%s", 1,
			       parc, parv) != HUNTED_ISME)
			return;

		parv[1] = parv[2];
	}

	do_whois(source_p, parc, parv);
}

/*
** mo_whois
**      parv[0] = sender prefix
**      parv[1] = nickname masklist
*/
static void
mo_whois(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	if(parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN), me.name, source_p->name);
		return;
	}

	if(parc > 2 && !EmptyString(parv[2]))
	{
		if(hunt_server(client_p, source_p, ":%s WHOIS %s :%s", 1,
			       parc, parv) != HUNTED_ISME)
			return;

		parv[1] = parv[2];
	}

	do_whois(source_p, parc, parv);
}

/* do_whois()
 *
 * inputs	- pointer to /whois source
 *              - number of parameters
 *              - pointer to parameters array
 * output	- pointer to void
 * side effects - Does whois
 */
static void
do_whois(struct Client *source_p, int parc, char **parv)
{
	static time_t last_used = 0;
	struct Client *target_p;
	char *nick;
	char *p = NULL;
	int found = 0;

	nick = parv[1];
	while(*nick == ',')
		nick++;
	if((p = strchr(nick, ',')) != NULL)
		*p = '\0';

	if(*nick == '\0')
		return;

	collapse(nick);

	if(strpbrk(nick, "?#*") == NULL)
	{
		if((target_p = find_client(nick)) != NULL)
		{
			if(IsServer(source_p->from))
				client_burst_if_needed(source_p->from, target_p);

			if(IsClient(target_p))
			{
				whois_person(source_p, target_p);
				found = 1;
			}
		}
		else if(!ServerInfo.hub && uplink && IsCapable(uplink, CAP_LL))
		{
			if(parc > 2)
				sendto_one(uplink, ":%s WHOIS %s :%s", source_p->name, nick, nick);
			else
				sendto_one(uplink, ":%s WHOIS %s", source_p->name, nick);
			return;
		}
	}
	else			/* wilds is true */
	{
		/* disallow wild card whois on lazylink leafs for now */
		if(!ServerInfo.hub && uplink && IsCapable(uplink, CAP_LL))
			return;

		if(!IsOper(source_p))
		{
			if((last_used + ConfigFileEntry.pace_wait_simple) > CurrentTime)
			{
				sendto_one(source_p, form_str(RPL_LOAD2HI),
					   me.name, source_p->name);
				return;
			}
			else
				last_used = CurrentTime;
		}

		/* Oh-oh wilds is true so have to do it the hard expensive way */
		if(MyClient(source_p))
			found = global_whois(source_p, nick);
	}

	if(!found)
	{
		if(!IsDigit(*nick))
			sendto_one(source_p, form_str(ERR_NOSUCHNICK),
				   me.name, source_p->name, nick);
	}

	sendto_one(source_p, form_str(RPL_ENDOFWHOIS), me.name, source_p->name, parv[1]);
}

/* global_whois()
 *
 * Inputs	- source_p client to report to
 *		- target_p client to report on
 * Output	- if found return 1
 * Side Effects	- do a single whois on given client
 * 		  writing results to source_p
 */
static int
global_whois(struct Client *source_p, const char *nick)
{
	dlink_node *ptr;
	struct Client *target_p;
	int found = 0;

	DLINK_FOREACH(ptr, global_client_list.head)
	{
		target_p = ptr->data;

		if(!IsClient(target_p))
			continue;

		if(!match(nick, target_p->name))
			continue;

		assert(target_p->servptr != NULL);

		/* 'Rules' established for sending a WHOIS reply:
		 *
		 *
		 * - if wildcards are being used dont send a reply if
		 *   the querier isnt any common channels and the
		 *   client in question is invisible and wildcards are
		 *   in use (allow exact matches only);
		 *
		 * - only send replies about common or public channels
		 *   the target user(s) are on;
		 */

		found |= single_whois(source_p, target_p);
	}

	return (found);
}

/* single_whois()
 *
 * Inputs	- source_p client to report to
 *		- target_p client to report on
 * Output	- if found return 1
 * Side Effects	- do a single whois on given client
 * 		  writing results to source_p
 */
static int
single_whois(struct Client *source_p, struct Client *target_p)
{
	dlink_node *ptr;
	struct Channel *chptr;

	if(!IsInvisible(target_p) || target_p == source_p)
	{
		/* always show user if they are visible (no +i) */
		whois_person(source_p, target_p);
		return 1;
	}

	/* target_p is +i. Check if it is on any common channels with source_p */
	DLINK_FOREACH(ptr, target_p->channel.head)
	{
		chptr = ((struct Membership *) ptr->data)->chptr;
		if(IsMember(source_p, chptr))
		{
			whois_person(source_p, target_p);
			return 1;
		}
	}

	return 0;
}

/* whois_person()
 *
 * inputs	- source_p client to report to
 *		- target_p client to report on
 * output	- NONE
 * side effects	- 
 */
static void
whois_person(struct Client *source_p, struct Client *target_p)
{
	char buf[IRCD_BUFSIZE];
	dlink_node *lp;
	struct Client *server_p;
	struct Channel *chptr;
	struct Membership *ms;
	int cur_len = 0;
	int mlen;
	char *t = NULL;
	int tlen;
	int reply_to_send = NO;
	int visible;
	static char authflags[14]; 
	char *prefix_ptr; 

	server_p = target_p->servptr;

	sendto_one(source_p, form_str(RPL_WHOISUSER),
		   me.name, source_p->name, target_p->name,
		   target_p->username, target_p->host, target_p->info);

	cur_len = mlen = ircsprintf(buf, form_str(RPL_WHOISCHANNELS),
				    me.name, source_p->name, target_p->name, "");
	t = buf + mlen;

	DLINK_FOREACH(lp, target_p->channel.head)
	{
		ms = lp->data;
		chptr = ms->chptr;

		visible = ShowChannel(source_p, target_p, chptr);

		if(visible || IsAdmin(source_p))
		{
			/* Don't show local channels if user is doing a remote whois */
			if(!MyConnect(source_p) && (chptr->chname[0] == '&'))
				continue;

			if((cur_len + 3 + strlen(chptr->chname) + 1) > (IRCD_BUFSIZE - 2))
			{
				*(t - 1) = '\0';
				sendto_one(source_p, "%s", buf);
				cur_len = mlen;
				t = buf + mlen;
			}

			tlen = ircsprintf(t, "%s%s%s ", visible ? "" : "!",
					  get_member_status(ms, NO, NO), chptr->chname);
			t += tlen;
			cur_len += tlen;
			reply_to_send = YES;
		}
	}

	if(reply_to_send)
	{
		*(t - 1) = '\0';
		sendto_one(source_p, "%s", buf);
	}

	if(IsOper(source_p) || !ConfigServerHide.hide_servers || target_p == source_p)
		sendto_one(source_p, form_str(RPL_WHOISSERVER),
			   me.name, source_p->name, target_p->name, server_p->name, server_p->info);
	else
		sendto_one(source_p, form_str(RPL_WHOISSERVER),
			   me.name, source_p->name, target_p->name,
			   ConfigServerHide.hidden_name, ServerInfo.network_desc);

	if(target_p->away != NULL)
		sendto_one(source_p, form_str(RPL_AWAY),
			   me.name, source_p->name, target_p->name, target_p->away);

	if(IsSetCallerId(target_p))
	{
		int notsoft = IsCallerId(target_p);

		sendto_one(source_p, form_str(RPL_TARGUMODEG),
			   me.name, source_p->name, target_p->name,
			   notsoft ? "+g" : "+G",
			   notsoft ? "server side ignore" :
			   "server side ignore with the exception of common channels");

	}

	if(IsOper(target_p))
	{
		buf[0] = '\0';

		strcat(buf, "is an IRC Operator");

		if(IsNetAdmin(target_p))
			strcat(buf, " - Network Administrator");
		else if(IsAdmin(target_p) && !IsOperHiddenAdmin(target_p))
			strcat(buf, " - Server Administrator");

		if(buf[0])
			sendto_one(source_p, form_str(RPL_WHOISOPERATOR),
				   me.name, source_p->name, target_p->name, buf);
	}

	if(IsOper(source_p) && IsCaptured(target_p))
		sendto_one(source_p, form_str(RPL_ISCAPTURED),
			   me.name, source_p->name, target_p->name);

	if(IsRegNick(target_p)) {
		if ((target_p == source_p || IsOper (source_p)) &&
		    !EmptyString (target_p->suser)) {
			sendto_one(source_p, form_str(RPL_WHOISREGNICK),
				   me.name, source_p->name, target_p->name, target_p->suser);
		}
		else
		sendto_one(source_p, form_str(RPL_WHOISREGNICK),
			   me.name, source_p->name, target_p->name, "this nick");
	}

	if(IsSSL(target_p)) {
		sendto_one(source_p, form_str(RPL_WHOISSSL),
			   me.name, source_p->name, target_p->name);
		
		if ((target_p == source_p || IsOper (source_p)) &&
		    !EmptyString (target_p->certfp)) {
			sendto_one(source_p, form_str(RPL_WHOISCERTFP),
				   me.name, source_p->name, target_p->name);
		}
	}

	if(IsWebIrc(target_p))
	{	
		buf[0] = '\0';
		if(IsOper(source_p) && MyClient(target_p))
		{
			strcat(buf, "from [");
			strcat(buf, target_p->localClient->cgisockhost);
			strcat(buf, "]");
		}
		sendto_one(source_p, form_str(RPL_WHOISCGI),
			   me.name, source_p->name, target_p->name, buf);
	}

	if(IsOper(source_p) || source_p == target_p)
	{
		char ubuf[IRCD_BUFSIZE];
		if(IsOperHiddenAdmin(target_p))
		{	
			send_umode(NULL, target_p, 0, (source_p == target_p) ?
				   0xffffffff : 0xffffffff & ~UMODE_ADMIN, ubuf);
		}
		else
		{
			send_umode(NULL, target_p, 0, 0xffffffff, ubuf);
		}

		if(*ubuf == '\0')
		{
			ubuf[0] = '+';
			ubuf[1] = '\0';
		}
		prefix_ptr = authflags;
		if(IsExemptResv(target_p))
			*prefix_ptr++ = '$';
		if(IsIPSpoof(target_p))
			*prefix_ptr++ = '=';
		if(IsExemptKline(target_p))
			*prefix_ptr++ = '^';
		if(IsExemptGline(target_p))
			*prefix_ptr++ = '_';
		if(IsExemptLimits(target_p))
			*prefix_ptr++ = '>';
		if(IsExemptDnsbl(target_p))
			*prefix_ptr++ = '~';
		if(IsIdlelined(target_p))
			*prefix_ptr++ = '<';
		if(IsCanFlood(target_p))
			*prefix_ptr++ = '|'; 
		*prefix_ptr = '\0';
		if(strlen(authflags) > 0)
			sendto_one(source_p, form_str(RPL_WHOISMODES),
				   me.name, source_p->name, target_p->name, ubuf, authflags);
		else
			sendto_one(source_p, form_str(RPL_WHOISMODES),
				   me.name, source_p->name, target_p->name, ubuf, "[none]");
	}

	if(ConfigFileEntry.use_whois_actually)
	{
		int hide_ip = 0;

		if(EmptyString(target_p->sockhost))
			hide_ip = 1;
		else if(!strcmp(target_p->sockhost, "0"))
			hide_ip = 1;
		else if(IsIPSpoof(target_p) && ConfigFileEntry.hide_spoof_ips)
			hide_ip = 1;

		if(IsOper(source_p) || source_p == target_p)
			sendto_one(source_p, form_str(RPL_WHOISACTUALLY), me.name,
				   source_p->name, target_p->name,
				   target_p->username, target_p->realhost,
				   hide_ip ? "255.255.255.255" : target_p->sockhost);
	}
	
	if(!IsHideChannels(target_p) || IsOper(source_p) || source_p == target_p)
	{
		if(MyClient(target_p))	/* Can't do any of this if not local! db */
			sendto_one(source_p, form_str(RPL_WHOISIDLE),
				   me.name, source_p->name, target_p->name,
				   CurrentTime - target_p->localClient->last, target_p->firsttime);
	}

#ifdef RIZON
	if(source_p != target_p && IsOper(target_p) && IsSpy(target_p))
		sendto_one(target_p,
			   ":%s NOTICE %s :*** Notice -- %s (%s@%s) is doing a whois on you [%s]",
			   ID_or_name(&me, target_p->from), ID_or_name(target_p, target_p->from),
			   source_p->name, source_p->username, source_p->realhost,
			   source_p->servptr->name);
#endif
}
