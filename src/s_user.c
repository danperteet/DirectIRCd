/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_user.c: User related functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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
 *  $Id: s_user.c 24001 2007-07-17 15:07:43Z androsyn $
 */

#include "stdinc.h"
#include "tools.h"
#include "s_user.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "hash.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "ircd.h"
#include "listener.h"
#include "msg.h"
#include "numeric.h"
#include "commio.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "s_serv.h"
#include "s_stats.h"
#include "scache.h"
#include "send.h"
#include "supported.h"
#include "whowas.h"
#include "memory.h"
#include "packet.h"
#include "reject.h"
#include "cache.h"
#include "hook.h"
#include "monitor.h"

static void report_and_set_user_flags(struct Client *, struct ConfItem *);
void user_welcome(struct Client *source_p);

extern char *crypt();

/* table of ascii char letters to corresponding bitmask */

struct flag_item
{
	int mode;
	char letter;
};

/* *INDENT-OFF* */
static struct flag_item user_modes[] = {
	{UMODE_ADMIN,		'a'},
	{UMODE_BOTS,		'b'},
	{UMODE_CCONN,		'c'},
	{UMODE_CCONNEXT,	'C'},
	{UMODE_DEBUG,		'd'},
	{UMODE_DEAF,		'D'},
	{UMODE_FULL,		'f'},
	{UMODE_CALLERID,	'g'},
	{UMODE_INVISIBLE,	'i'},
	{UMODE_SKILL,		'k'},
	{UMODE_LOCOPS,		'l'},
	{UMODE_NCHANGE,		'n'},
	{UMODE_OPER,		'o'},
	{UMODE_REJ,		'r'},
	{UMODE_SERVNOTICE,	's'},
#ifdef ENABLE_SERVICES
	{UMODE_SERVICE,		'S'},
#endif
	{UMODE_UNAUTH,		'u'},
	{UMODE_WALLOP,		'w'},
	{UMODE_EXTERNAL,	'x'},
	{UMODE_SPY,		'y'},
	{UMODE_OPERWALL,	'z'},
	{UMODE_OPERSPY,		'Z'},
	{0, 0}
};

/* memory is cheap. map 0-255 to equivalent mode */
int user_modes_from_c_to_bitmask[] = {
	/* 0x00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x0F */
	/* 0x10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x1F */
	/* 0x20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x2F */
	/* 0x30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x3F */
	0,			/* @ */
	0,			/* A */
	0,			/* B */
	UMODE_CCONNEXT,		/* C */
	UMODE_DEAF,		/* D */
	0,			/* E */
	0,			/* F */
	0,			/* G */
	0,			/* H */
	0,			/* I */
	0,			/* J */
	0,			/* K */
	0,			/* L */
	0,			/* M */
	0,			/* N */
	0,			/* O */
	0,			/* P */
	0,			/* Q */
	0,			/* R */
#ifdef ENABLE_SERVICES
	UMODE_SERVICE,		/* S */
#else
	0,			/* S */
#endif
	0,			/* T */
	0,			/* U */
	0,			/* V */
	0,			/* W */
	0,			/* X */
	0,			/* Y */
	UMODE_OPERSPY,		/* Z */
	/* 0x5B */ 0, 0, 0, 0, 0, 0, /* 0x60 */
	UMODE_ADMIN,		/* a */
	UMODE_BOTS,		/* b */
	UMODE_CCONN,		/* c */
	UMODE_DEBUG,		/* d */
	0,			/* e */
	UMODE_FULL,		/* f */
	UMODE_CALLERID,		/* g */
	0,			/* h */
	UMODE_INVISIBLE,	/* i */
	0,			/* j */
	UMODE_SKILL,		/* k */
	UMODE_LOCOPS,		/* l */
	0,			/* m */
	UMODE_NCHANGE,		/* n */
	UMODE_OPER,		/* o */
	0,			/* p */
	0,			/* q */
	UMODE_REJ,		/* r */
	UMODE_SERVNOTICE,	/* s */
	0,			/* t */
	UMODE_UNAUTH,		/* u */
	0,			/* v */
	UMODE_WALLOP,		/* w */
	UMODE_EXTERNAL,		/* x */
	UMODE_SPY,		/* y */
	UMODE_OPERWALL,		/* z */
	/* 0x7B */ 0, 0, 0, 0, 0, /* 0x7F */
	/* 0x80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x9F */
	/* 0x90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x9F */
	/* 0xA0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xAF */
	/* 0xB0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xBF */
	/* 0xC0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xCF */
	/* 0xD0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xDF */
	/* 0xE0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xEF */
	/* 0xF0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* 0xFF */
};
/* *INDENT-ON* */

/*
 * show_lusers -
 *
 * inputs	- pointer to client
 * output	-
 * side effects	- display to client user counts etc.
 */
int
show_lusers(struct Client *source_p)
{
	sendto_one_numeric(source_p, RPL_LUSERCLIENT, form_str(RPL_LUSERCLIENT),
			   (Count.total - Count.invisi),
			   Count.invisi, dlink_list_length(&global_serv_list));

	if(Count.oper > 0)
		sendto_one_numeric(source_p, RPL_LUSEROP, 
				   form_str(RPL_LUSEROP), Count.oper);

	if(dlink_list_length(&unknown_list) > 0)
		sendto_one_numeric(source_p, RPL_LUSERUNKNOWN, 
				   form_str(RPL_LUSERUNKNOWN),
				   dlink_list_length(&unknown_list));

	if(dlink_list_length(&global_channel_list) > 0)
		sendto_one_numeric(source_p, RPL_LUSERCHANNELS, 
				   form_str(RPL_LUSERCHANNELS),
				   dlink_list_length(&global_channel_list));

	sendto_one_numeric(source_p, RPL_LUSERME, form_str(RPL_LUSERME),
			   dlink_list_length(&lclient_list),
			   dlink_list_length(&serv_list));

	sendto_one_numeric(source_p, RPL_LOCALUSERS, 
			   form_str(RPL_LOCALUSERS),
			   dlink_list_length(&lclient_list),
			   Count.max_loc,
			   dlink_list_length(&lclient_list),
			   Count.max_loc);

	sendto_one_numeric(source_p, RPL_GLOBALUSERS, form_str(RPL_GLOBALUSERS),
			   Count.total, Count.max_tot,
			   Count.total, Count.max_tot);

	sendto_one_numeric(source_p, RPL_STATSCONN,
			   form_str(RPL_STATSCONN),
			   MaxConnectionCount, MaxClientCount, 
			   Count.totalrestartcount);

	if(dlink_list_length(&lclient_list) > (unsigned long)MaxClientCount)
		MaxClientCount = dlink_list_length(&lclient_list);

	if((dlink_list_length(&lclient_list) + dlink_list_length(&serv_list)) >
	   (unsigned long)MaxConnectionCount)
		MaxConnectionCount = dlink_list_length(&lclient_list) + 
					dlink_list_length(&serv_list);

	return 0;
}

/*
 * show_isupport
 *
 * inputs	- pointer to client
 * output	- 
 * side effects	- display to client what we support (for them)
 */
void
show_isupport(struct Client *source_p)
{
	char isupportbuffer[512];

	ircsprintf(isupportbuffer, FEATURES, FEATURESVALUES);
	sendto_one_numeric(source_p, RPL_ISUPPORT, form_str(RPL_ISUPPORT), isupportbuffer);

	ircsprintf(isupportbuffer, FEATURES2, FEATURES2VALUES);
	sendto_one_numeric(source_p, RPL_ISUPPORT, form_str(RPL_ISUPPORT), isupportbuffer);

	ircsprintf(isupportbuffer, FEATURES3, FEATURES3VALUES);
	sendto_one_numeric(source_p, RPL_ISUPPORT, form_str(RPL_ISUPPORT), isupportbuffer);

	return;
}


/*
** register_local_user
**      This function is called when both NICK and USER messages
**      have been accepted for the client, in whatever order. Only
**      after this, is the USER message propagated.
**
**      NICK's must be propagated at once when received, although
**      it would be better to delay them too until full info is
**      available. Doing it is not so simple though, would have
**      to implement the following:
**
**      (actually it has been implemented already for a while) -orabidoo
**
**      1) user telnets in and gives only "NICK foobar" and waits
**      2) another user far away logs in normally with the nick
**         "foobar" (quite legal, as this server didn't propagate
**         it).
**      3) now this server gets nick "foobar" from outside, but
**         has alread the same defined locally. Current server
**         would just issue "KILL foobar" to clean out dups. But,
**         this is not fair. It should actually request another
**         nick from local user or kill him/her...
*/

int
register_local_user(struct Client *client_p, struct Client *source_p, const char *username)
{
	struct ConfItem *aconf;
	struct User *user = source_p->user;
	char tmpstr2[IRCD_BUFSIZE];
	char ipaddr[HOSTIPLEN];
	char myusername[USERLEN+1];
	int status;

	s_assert(NULL != source_p);
	s_assert(MyConnect(source_p));
	s_assert(source_p->username != username);

	if(source_p == NULL)
		return -1;

	if(IsAnyDead(source_p))
		return -1;

	if(ConfigFileEntry.ping_cookie)
	{
		if(!(source_p->flags & FLAGS_PINGSENT) && source_p->localClient->random_ping == 0)
		{
			source_p->localClient->random_ping = (unsigned long) (rand() * rand()) << 1;
			sendto_one(source_p, "PING :%08lX",
				   (unsigned long) source_p->localClient->random_ping);
			source_p->flags |= FLAGS_PINGSENT;
			return -1;
		}
		if(!(source_p->flags2 & FLAGS2_PING_COOKIE))
		{
			return -1;
		}
	}

	/* hasnt finished client cap negotiation */
	if(source_p->flags2 & FLAGS2_CLICAP)
		return -1;

	client_p->localClient->last = CurrentTime;
	/* Straight up the maximum rate of flooding... */
	source_p->localClient->allow_read = MAX_FLOOD_BURST;

	/* XXX - fixme. we shouldnt have to build a users buffer twice.. */
	if(!IsGotId(source_p) && (strchr(username, '[') != NULL))
	{
		const char *p;
		int i = 0;

		p = username;

		while(*p && i < USERLEN)
		{
			if(*p != '[')
				myusername[i++] = *p;
			p++;
		}

		myusername[i] = '\0';
		username = myusername;
	}

	if((status = check_client(client_p, source_p, username)) < 0)
		return (CLIENT_EXITED);

	if(!valid_hostname(source_p->host))
	{
		sendto_one(source_p,
			   ":%s NOTICE %s :*** Notice -- You have an illegal character in your hostname",
			   me.name, source_p->name);

		strlcpy(source_p->host, source_p->sockhost, sizeof(source_p->host));

#ifdef IPV6
		if(ConfigFileEntry.dot_in_ip6_addr == 1)
			strlcat(source_p->host, ".", sizeof(source_p->host));
#endif
 	}
 

	aconf = source_p->localClient->att_conf;

	if(aconf == NULL)
	{
		exit_client(client_p, source_p, &me, "*** Not Authorised");
		return (CLIENT_EXITED);
	}

	if(!IsGotId(source_p))
	{
		const char *p;
		int i = 0;

		if(IsNeedIdentd(aconf))
		{
			ServerStats->is_ref++;
			sendto_one(source_p,
				   ":%s NOTICE %s :*** Notice -- You need to install identd to use this server",
				   me.name, client_p->name);
			exit_client(client_p, source_p, &me, "Install identd");
			return (CLIENT_EXITED);
		}

		/* dont replace username if its supposed to be spoofed --fl */
		if(!IsConfDoSpoofIp(aconf) || !strchr(aconf->name, '@'))
		{
			p = username;

			if(!IsNoTilde(aconf))
				source_p->username[i++] = '~';

			while (*p && i < USERLEN)
			{
				if(*p != '[')
					source_p->username[i++] = *p;
				p++;
			}

			source_p->username[i] = '\0';
		}
	}

	/* password check */
	if(!EmptyString(aconf->passwd))
	{
		const char *encr;

		if(EmptyString(source_p->localClient->passwd))
			encr = "";
		else if(IsConfEncrypted(aconf))
			encr = crypt(source_p->localClient->passwd, aconf->passwd);
		else
			encr = source_p->localClient->passwd;

		if(strcmp(encr, aconf->passwd))
		{
			ServerStats->is_ref++;
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);
			exit_client(client_p, source_p, &me, "Bad Password");
			return (CLIENT_EXITED);
		}
	}

	if(source_p->localClient->passwd)
	{
		memset(source_p->localClient->passwd, 0, strlen(source_p->localClient->passwd));
		MyFree(source_p->localClient->passwd);
		source_p->localClient->passwd = NULL;
	}

	/* report if user has &^>= etc. and set flags as needed in source_p */
	report_and_set_user_flags(source_p, aconf);

	/* Limit clients */
	/*
	 * We want to be able to have servers and F-line clients
	 * connect, so save room for "buffer" connections.
	 * Smaller servers may want to decrease this, and it should
	 * probably be just a percentage of the MAXCLIENTS...
	 *   -Taner
	 */
	/* Except "F:" clients */
	if(((dlink_list_length(&lclient_list) + 1) >= 
	   ((unsigned long)GlobalSetOptions.maxclients + MAX_BUFFER) ||
           (dlink_list_length(&lclient_list) + 1) >= 
	    ((unsigned long)GlobalSetOptions.maxclients - 5)) && !(IsExemptLimits(source_p)))
	{
		sendto_realops_flags(UMODE_FULL, L_ALL,
				     "Too many clients, rejecting %s[%s].", source_p->name, source_p->host);

		ServerStats->is_ref++;
		exit_client(client_p, source_p, &me, "Sorry, server is full - try later");
		return (CLIENT_EXITED);
	}

	/* valid user name check */

	if(!valid_username(source_p->username))
	{
		sendto_realops_flags(UMODE_REJ, L_ALL,
				     "Invalid username: %s (%s@%s)",
				     source_p->name, source_p->username, source_p->host);
		ServerStats->is_ref++;
		ircsprintf(tmpstr2, "Invalid username [%s]", source_p->username);
		exit_client(client_p, source_p, &me, tmpstr2);
		return (CLIENT_EXITED);
	}

	/* end of valid user name check */

	/* kline exemption extends to xline too */
	if(!IsExemptKline(source_p) &&
	   find_xline(source_p->info, 1) != NULL)
	{
		ServerStats->is_ref++;
		add_reject(source_p);
		exit_client(client_p, source_p, &me, "Bad user info");
		return CLIENT_EXITED;
	}

	if(IsAnyDead(client_p))
		return CLIENT_EXITED;

	inetntop_sock((struct sockaddr *)&source_p->localClient->ip, ipaddr, sizeof(ipaddr));

	sendto_realops_flags(UMODE_CCONN, L_ALL,
			     "Client connecting: %s (%s@%s) [%s] {%s} [%s]",
			     source_p->name, source_p->username, source_p->host,
			     show_ip(NULL, source_p) ? ipaddr : "255.255.255.255",
			     get_client_class(source_p), source_p->info);

	sendto_realops_flags(UMODE_CCONNEXT, L_ALL,
			"CLICONN %s %s %s %s %s %s 0 %s",
			source_p->name, source_p->username, source_p->host,
			show_ip(NULL, source_p) ? ipaddr : "255.255.255.255",
			get_client_class(source_p),
			/* mirc can sometimes send ips here */
			show_ip(NULL, source_p) ? source_p->localClient->fullcaps : 
			 "<hidden> <hidden>", 
			source_p->info);

	/* If they have died in send_* don't do anything. */
	if(IsAnyDead(source_p))
		return CLIENT_EXITED;

	add_to_hostname_hash(source_p->host, source_p);

	strcpy(source_p->id, generate_uid());
	add_to_id_hash(source_p->id, source_p);

	if(ConfigFileEntry.default_invisible)
	{
		source_p->umodes |= UMODE_INVISIBLE;
		Count.invisi++;
	}

	s_assert(!IsClient(source_p));
	del_unknown_ip(source_p);
	dlinkMoveNode(&source_p->localClient->tnode, &unknown_list, &lclient_list);
	SetClient(source_p);

	/* XXX source_p->servptr is &me, since local client */
	/* NO SHIT!^*($^, so lets not use the below. --fl */
	/* source_p->servptr = find_server(NULL, user->server); */
	source_p->servptr = &me;

	dlinkAdd(source_p, &source_p->lnode, &source_p->servptr->serv->users);
	/* Increment our total user count here */
	if(++Count.total > Count.max_tot)
		Count.max_tot = Count.total;
	source_p->localClient->allow_read = MAX_FLOOD_BURST;

	Count.totalrestartcount++;

	s_assert(source_p->localClient != NULL);

	if(dlink_list_length(&lclient_list) > (unsigned long)Count.max_loc)
	{
		Count.max_loc = dlink_list_length(&lclient_list);
		if(!(Count.max_loc % 10))
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "New Max Local Clients: %d", Count.max_loc);
	}

	/* they get a reduced limit */
	if(find_tgchange(source_p->sockhost))
		USED_TARGETS(source_p) = 6;

	monitor_signon(source_p);
	user_welcome(source_p);
	introduce_client(client_p, source_p, user, source_p->name);
	return 0;
}

/*
 * introduce_clients
 *
 * inputs	-
 * output	-
 * side effects - This common function introduces a client to the rest
 *		  of the net, either from a local client connect or
 *		  from a remote connect.
 */
void
introduce_client(struct Client *client_p, struct Client *source_p, struct User *user, const char *nick)
{
	static char ubuf[12];

	if(MyClient(source_p))
		send_umode(source_p, source_p, 0, SEND_UMODES, ubuf);
	else
		send_umode(NULL, source_p, 0, SEND_UMODES, ubuf);

	if(!*ubuf)
	{
		ubuf[0] = '+';
		ubuf[1] = '\0';
	}

	/* if it has an ID, introduce it with its id to TS6 servers,
	 * otherwise introduce it normally to all.
	 */
	if(has_id(source_p))
	{
		char sockhost[HOSTLEN];
		if(source_p->sockhost[0] == ':')
		{
			sockhost[0] = '0';
			sockhost[1] = '\0';
			strlcat(sockhost, source_p->sockhost, sizeof(sockhost));
		} else
			strcpy(sockhost, source_p->sockhost);
		
		sendto_server(client_p, NULL, CAP_TS6, NOCAPS,
			      ":%s UID %s %d %ld %s %s %s %s %s :%s",
			      source_p->servptr->id, nick,
			      source_p->hopcount + 1,
			      (long) source_p->tsinfo, ubuf,
			      source_p->username, source_p->host,
			      IsIPSpoof(source_p) ? "0" : sockhost,
			      source_p->id, source_p->info);

		sendto_server(client_p, NULL, NOCAPS, CAP_TS6,
			      "NICK %s %d %ld %s %s %s %s :%s",
			      nick, source_p->hopcount + 1,
			      (long) source_p->tsinfo,
			      ubuf, source_p->username, source_p->host,
			      source_p->servptr->name, source_p->info);
	}
	else
		sendto_server(client_p, NULL, NOCAPS, NOCAPS,
			      "NICK %s %d %ld %s %s %s %s :%s",
			      nick, source_p->hopcount + 1,
			      (long) source_p->tsinfo,
			      ubuf, source_p->username, source_p->host,
			      source_p->servptr->name, source_p->info);
}

/* 
 * valid_hostname - check hostname for validity
 *
 * Inputs       - pointer to user
 * Output       - YES if valid, NO if not
 * Side effects - NONE
 *
 * NOTE: this doesn't allow a hostname to begin with a dot and
 * will not allow more dots than chars.
 */
int
valid_hostname(const char *hostname)
{
	const char *p = hostname;
	int found_sep = 0;

	s_assert(NULL != p);

	if(hostname == NULL)
		return NO;

	if('.' == *p || ':' == *p)
		return NO;

	while (*p)
	{
		if(!IsHostChar(*p))
			return NO;
                if(*p == '.' || *p == ':')
  			found_sep++;
		p++;
	}

	if(found_sep == 0)
		return(NO);

	return (YES);
}

/* 
 * valid_username - check username for validity
 *
 * Inputs       - pointer to user
 * Output       - YES if valid, NO if not
 * Side effects - NONE
 * 
 * Absolutely always reject any '*' '!' '?' '@' in an user name
 * reject any odd control characters names.
 * Allow '.' in username to allow for "first.last"
 * style of username
 */
int
valid_username(const char *username)
{
	int dots = 0;
	const char *p = username;

	s_assert(NULL != p);

	if(username == NULL)
		return NO;

	if('~' == *p)
		++p;

	/* reject usernames that don't start with an alphanum
	 * i.e. reject jokers who have '-@somehost' or '.@somehost'
	 * or "-hi-@somehost", "h-----@somehost" would still be accepted.
	 */
	if(!IsAlNum(*p))
		return NO;

	while (*++p)
	{
		if((*p == '.') && ConfigFileEntry.dots_in_ident)
		{
			dots++;
			if(dots > ConfigFileEntry.dots_in_ident)
				return NO;
			if(!IsUserChar(p[1]))
				return NO;
		}
		else if(!IsUserChar(*p))
			return NO;
	}
	return YES;
}

/* report_and_set_user_flags
 *
 * Inputs       - pointer to source_p
 *              - pointer to aconf for this user
 * Output       - NONE
 * Side effects -
 * Report to user any special flags they are getting, and set them.
 */

static void
report_and_set_user_flags(struct Client *source_p, struct ConfItem *aconf)
{
	/* If this user is being spoofed, tell them so */
	if(IsConfDoSpoofIp(aconf))
	{
		sendto_one(source_p,
			   ":%s NOTICE %s :*** Spoofing your IP. congrats.",
			   me.name, source_p->name);
	}

	/* If this user is in the exception class, Set it "E lined" */
	if(IsConfExemptKline(aconf))
	{
		SetExemptKline(source_p);
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You are exempt from K/D/G/X lines. congrats.",
			   me.name, source_p->name);
	}

	if(IsConfExemptGline(aconf))
	{
		SetExemptGline(source_p);

		/* dont send both a kline and gline exempt notice */
		if(!IsConfExemptKline(aconf))
			sendto_one(source_p,
				   ":%s NOTICE %s :*** You are exempt from G lines.",
				   me.name, source_p->name);
	}

	/* If this user is exempt from user limits set it F lined" */
	if(IsConfExemptLimits(aconf))
	{
		SetExemptLimits(source_p);
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You are exempt from user limits. congrats.",
			   me.name, source_p->name);
	}

	if(IsConfExemptFlood(aconf))
	{
		SetExemptFlood(source_p);
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You are exempt from flood limits.",
			   me.name, source_p->name);
	}

	if(IsConfExemptSpambot(aconf))
	{
		SetExemptSpambot(source_p);
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You are exempt from spambot checks.",
			   me.name, source_p->name);
	}

	if(IsConfExemptJupe(aconf))
	{
		SetExemptJupe(source_p);
		sendto_one(source_p,
				":%s NOTICE %s :*** You are exempt from juped channel warnings.",
				me.name, source_p->name);
	}

	if(IsConfExemptResv(aconf))
	{
		SetExemptResv(source_p);
		sendto_one(source_p,
				":%s NOTICE %s :*** You are exempt from resvs.",
				me.name, source_p->name);
	}

	if(IsConfExemptShide(aconf))
	{
		SetExemptShide(source_p);
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You are exempt from serverhiding.",
			   me.name, source_p->name);
	}
}

/*
 * user_mode - set get current users mode
 *
 * m_umode() added 15/10/91 By Darren Reed.
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int
user_mode(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	int flag;
	int i;
	const char **p;
	char *m;
	const char *pm;
	struct Client *target_p;
	int what, setflags;
	int badflag = NO;	/* Only send one bad flag notice */
	char buf[BUFSIZE];

	what = MODE_ADD;

	if(parc < 2)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "MODE");
		return 0;
	}

	if((target_p = MyClient(source_p) ? find_named_person(parv[1]) : find_person(parv[1])) == NULL)
	{
		if(MyConnect(source_p))
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
					   form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}

	/* Dont know why these were commented out..
	 * put them back using new sendto() funcs
	 */

	if(IsServer(source_p))
	{
		sendto_realops_flags(UMODE_ALL, L_ADMIN,
				     "*** Mode for User %s from %s", parv[1], source_p->name);
		return 0;
	}

	if(source_p != target_p || target_p->from != source_p->from)
	{
		sendto_one(source_p, form_str(ERR_USERSDONTMATCH), me.name, source_p->name);
		return 0;
	}


	if(parc < 3)
	{
		m = buf;
		*m++ = '+';

		for (i = 0; user_modes[i].letter && (m - buf < BUFSIZE - 4); i++)
			if(source_p->umodes & user_modes[i].mode)
				*m++ = user_modes[i].letter;
		*m = '\0';
		sendto_one(source_p, form_str(RPL_UMODEIS), me.name, source_p->name, buf);
		return 0;
	}

	/* find flags already set for user */
	setflags = source_p->umodes;

	/*
	 * parse mode change string(s)
	 */
	for (p = &parv[2]; p && *p; p++)
		for (pm = *p; *pm; pm++)
			switch (*pm)
			{
			case '+':
				what = MODE_ADD;
				break;
			case '-':
				what = MODE_DEL;
				break;

			case 'o':
				if(what == MODE_ADD)
				{
					if(IsServer(client_p) && !IsOper(source_p))
					{
						++Count.oper;
						SetOper(source_p);
					}
				}
				else
				{
					/* Only decrement the oper counts if an oper to begin with
					 * found by Pat Szuta, Perly , perly@xnet.com 
					 */

					if(!IsOper(source_p))
						break;

					ClearOper(source_p);

					Count.oper--;

					if(MyConnect(source_p))
					{
						source_p->umodes &= ~ConfigFileEntry.oper_only_umodes;
						source_p->flags2 &= ~OPER_FLAGS;

						MyFree(source_p->localClient->opername);
						source_p->localClient->opername = NULL;

						dlinkFindDestroy(source_p, &oper_list);
					}
				}
				break;

				/* we may not get these,
				 * but they shouldnt be in default
				 */

			/* can only be set on burst */
#ifdef ENABLE_SERVICES
			case 'S':
#endif
			case ' ':
			case '\n':
			case '\r':
			case '\t':
				break;

			default:
				if((flag = user_modes_from_c_to_bitmask[(unsigned char) *pm]))
				{
					if(MyConnect(source_p)
					   && !IsOper(source_p)
					   && (ConfigFileEntry.oper_only_umodes & flag))
					{
						badflag = YES;
					}
					else
					{
						if(what == MODE_ADD)
							source_p->umodes |= flag;
						else
							source_p->umodes &= ~flag;
					}
				}
				else
				{
					if(MyConnect(source_p))
						badflag = YES;
				}
				break;
			}

	if(badflag)
		sendto_one(source_p, form_str(ERR_UMODEUNKNOWNFLAG), me.name, source_p->name);

	if((source_p->umodes & UMODE_NCHANGE) && !IsOperN(source_p))
	{
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You need oper and N flag for +n", me.name, parv[0]);
		source_p->umodes &= ~UMODE_NCHANGE;	/* only tcm's really need this */
	}

	if(MyConnect(source_p) && (source_p->umodes & UMODE_ADMIN) &&
	   (!IsOperAdmin(source_p) || IsOperHiddenAdmin(source_p)))
	{
		sendto_one(source_p,
			   ":%s NOTICE %s :*** You need oper and A flag for +a", me.name, parv[0]);
		source_p->umodes &= ~UMODE_ADMIN;
	}


	if(!(setflags & UMODE_INVISIBLE) && IsInvisible(source_p))
		++Count.invisi;
	if((setflags & UMODE_INVISIBLE) && !IsInvisible(source_p))
		--Count.invisi;
	/*
	 * compare new flags with old flags and send string which
	 * will cause servers to update correctly.
	 */
	send_umode_out(client_p, source_p, setflags);

	return (0);
}

/*
 * send the MODE string for user (user) to connection client_p
 * -avalon
 */
void
send_umode(struct Client *client_p, struct Client *source_p, int old, int sendmask, char *umode_buf)
{
	int i;
	int flag;
	char *m;
	int what = 0;

	/*
	 * build a string in umode_buf to represent the change in the user's
	 * mode between the new (source_p->flag) and 'old'.
	 */
	m = umode_buf;
	*m = '\0';

	for (i = 0; user_modes[i].letter; i++)
	{
		flag = user_modes[i].mode;

		if(MyClient(source_p) && !(flag & sendmask))
			continue;
		if((flag & old) && !(source_p->umodes & flag))
		{
			if(what == MODE_DEL)
				*m++ = user_modes[i].letter;
			else
			{
				what = MODE_DEL;
				*m++ = '-';
				*m++ = user_modes[i].letter;
			}
		}
		else if(!(flag & old) && (source_p->umodes & flag))
		{
			if(what == MODE_ADD)
				*m++ = user_modes[i].letter;
			else
			{
				what = MODE_ADD;
				*m++ = '+';
				*m++ = user_modes[i].letter;
			}
		}
	}
	*m = '\0';
	if(*umode_buf && client_p)
		sendto_one(client_p, ":%s MODE %s :%s", source_p->name, source_p->name, umode_buf);
}

/*
 * send_umode_out
 *
 * inputs	-
 * output	- NONE
 * side effects - 
 */
void
send_umode_out(struct Client *client_p, struct Client *source_p, int old)
{
	struct Client *target_p;
	char buf[BUFSIZE];
	dlink_node *ptr;

	send_umode(NULL, source_p, old, SEND_UMODES, buf);

	DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if((target_p != client_p) && (target_p != source_p) && (*buf))
		{
			sendto_one(target_p, ":%s MODE %s :%s",
				   get_id(source_p, target_p), 
				   get_id(source_p, target_p), buf);
		}
	}

	if(client_p && MyClient(client_p))
		send_umode(client_p, source_p, old, ALL_UMODES, buf);
}

/* 
 * user_welcome
 *
 * inputs	- client pointer to client to welcome
 * output	- NONE
 * side effects	-
 */
void
user_welcome(struct Client *source_p)
{
	sendto_one(source_p, form_str(RPL_WELCOME), me.name, source_p->name,
		   ServerInfo.network_name, source_p->name);
	sendto_one(source_p, form_str(RPL_YOURHOST), me.name,
		   source_p->name,
		   get_listener_name(source_p->localClient->listener), ircd_version);

	sendto_one(source_p, form_str(RPL_CREATED), me.name, source_p->name, creation);
	sendto_one(source_p, form_str(RPL_MYINFO), me.name, source_p->name, me.name, ircd_version);

	show_isupport(source_p);

	show_lusers(source_p);

	if(ConfigFileEntry.short_motd)
	{
		sendto_one(source_p,
			   "NOTICE %s :*** Notice -- motd was last changed at %s",
			   source_p->name, user_motd_changed);

		sendto_one(source_p,
			   "NOTICE %s :*** Notice -- Please read the motd if you haven't read it",
			   source_p->name);

		sendto_one(source_p, form_str(RPL_MOTDSTART), 
			   me.name, source_p->name, me.name);

		sendto_one(source_p, form_str(RPL_MOTD),
			   me.name, source_p->name, "*** This is the short motd ***");

		sendto_one(source_p, form_str(RPL_ENDOFMOTD), me.name, source_p->name);
	}
	else
		send_user_motd(source_p);
}

/* oper_up()
 *
 * inputs	- pointer to given client to oper
 *		- pointer to ConfItem to use
 * output	- none
 * side effects	- opers up source_p using aconf for reference
 */
int
oper_up(struct Client *source_p, struct oper_conf *oper_p)
{
	int old = (source_p->umodes & ALL_UMODES);

	SetOper(source_p);

	if(oper_p->umodes)
		source_p->umodes |= oper_p->umodes & ALL_UMODES;
	else if(ConfigFileEntry.oper_umodes)
		source_p->umodes |= ConfigFileEntry.oper_umodes & ALL_UMODES;
	else
		source_p->umodes |= DEFAULT_OPER_UMODES & ALL_UMODES;

	Count.oper++;

	SetExemptKline(source_p);

	source_p->flags2 |= oper_p->flags;
	MyFree(source_p->localClient->opername);
	DupString(source_p->localClient->opername, oper_p->name);

	dlinkAddAlloc(source_p, &oper_list);

	if(IsOperAdmin(source_p) && !IsOperHiddenAdmin(source_p))
		source_p->umodes |= UMODE_ADMIN;
	if(!IsOperN(source_p))
		source_p->umodes &= ~UMODE_NCHANGE;

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s (%s@%s) is now an operator", source_p->name,
			     source_p->username, source_p->host);
	if(!(old & UMODE_INVISIBLE) && IsInvisible(source_p))
		++Count.invisi;
	if((old & UMODE_INVISIBLE) && !IsInvisible(source_p))
		--Count.invisi;
	send_umode_out(source_p, source_p, old);
	sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
	sendto_one(source_p, ":%s NOTICE %s :*** Oper privs are %s", me.name,
		   source_p->name, get_oper_privs(oper_p->flags));
	send_oper_motd(source_p);

	return (1);
}
