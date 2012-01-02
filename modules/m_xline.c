/* modules/m_xline.c
 * 
 *  Copyright (C) 2002-2003 Lee Hardy <lee@leeh.co.uk>
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: m_xline.c 24898 2008-01-11 18:59:30Z androsyn $
 */

#include "stdinc.h"
#include "tools.h"
#include "send.h"
#include "channel.h"
#include "client.h"
#include "common.h"
#include "config.h"
#include "class.h"
#include "ircd.h"
#include "numeric.h"
#include "memory.h"
#include "s_log.h"
#include "s_serv.h"
#include "whowas.h"
#include "irc_string.h"
#include "sprintf_irc.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "s_newconf.h"

static int mo_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int ms_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int ms_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message xline_msgtab = {
	"XLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, {ms_xline, 5}, {ms_xline, 5}, {me_xline, 5}, {mo_xline, 3}}
};
struct Message unxline_msgtab = {
	"UNXLINE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, {ms_unxline, 3}, {ms_unxline, 3}, {me_unxline, 2}, {mo_unxline, 2}}
};

mapi_clist_av1 xline_clist[] =  { &xline_msgtab, &unxline_msgtab, NULL };
DECLARE_MODULE_AV1(xline, NULL, NULL, xline_clist, NULL, NULL, "$Revision: 24898 $");

static int valid_xline(struct Client *, const char *, const char *, int temp);
static void apply_xline(struct Client *client_p, const char *name, 
			const char *reason, int temp_time);
static void write_xline(struct Client *source_p, struct ConfItem *aconf);
static void propagate_xline(struct Client *source_p, const char *target,
			int temp_time, const char *name, 
			const char *type, const char *reason);
static void cluster_xline(struct Client *source_p, int temp_time,
			const char *name, const char *reason);

static void handle_remote_xline(struct Client *source_p, int temp_time,
				const char *name, const char *reason);
static void handle_remote_unxline(struct Client *source_p, const char *name);

static int remove_temp_xline(struct Client *source_p, const char *name);
static void remove_xline(struct Client *source_p, const char *gecos);


/* m_xline()
 *
 * parv[1] - thing to xline
 * parv[2] - optional type/reason
 * parv[3] - reason
 */
static int
mo_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf;
	const char *name;
	const char *reason;
	const char *target_server = NULL;
	int temp_time;
	int loc = 1;

	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS),
			   me.name, source_p->name, "xline");
		return 0;
	}

	if((temp_time = valid_temp_time(parv[loc])) >= 0)
		loc++;
	/* we just set temp_time to -1! */
	else
		temp_time = 0;

	name = parv[loc];
	loc++;

	/* XLINE <gecos> ON <server> :<reason> */
	if(parc >= loc+2 && !irccmp(parv[loc], "ON"))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				me.name, source_p->name, "remoteban");
			return 0;
		}

		target_server = parv[loc+1];
		loc += 2;
	}

	if(parc <= loc || EmptyString(parv[loc]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "XLINE");
		return 0;
	}

	reason = parv[loc];

	if(target_server != NULL)
	{
		propagate_xline(source_p, target_server, temp_time,
				name, "2", reason);

		if(!match(target_server, me.name))
			return 0;
	}
	else if(dlink_list_length(&cluster_conf_list) > 0)
		cluster_xline(source_p, temp_time, name, reason);

	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one(source_p, ":%s NOTICE %s :[%s] already X-Lined by [%s] - %s",
			   me.name, source_p->name, parv[1], aconf->name, aconf->passwd);
		return 0;
	}

	if(!valid_xline(source_p, name, reason, temp_time))
		return 0;

	apply_xline(source_p, name, reason, temp_time);

	return 0;
}

/* ms_xline()
 *
 * handles a remote xline
 */
static int
ms_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* parv[0]  parv[1]      parv[2]  parv[3]  parv[4]
	 * oper     target serv  xline    type     reason
	 */
	propagate_xline(source_p, parv[1], 0, parv[2], parv[3], parv[4]);

	if(!IsPerson(source_p))
		return 0;

	/* destined for me? */
	if(!match(parv[1], me.name))
		return 0;

	handle_remote_xline(source_p, 0, parv[2], parv[4]);
	return 0;
}

static int
me_xline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* time name type :reason */
	if(!IsPerson(source_p))
		return 0;

	handle_remote_xline(source_p, atoi(parv[1]), parv[2], parv[4]);
	return 0;
}

static void
handle_remote_xline(struct Client *source_p, int temp_time,
			const char *name, const char *reason)
{
	struct ConfItem *aconf;

	if(!find_shared_conf(source_p->username, source_p->host,
				source_p->servptr->name,
				(temp_time > 0) ? SHARED_TXLINE : SHARED_PXLINE))
		return;

	if(!valid_xline(source_p, name, reason, temp_time))
		return;

	/* already xlined */
	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one(source_p, ":%s NOTICE %s :[%s] already X-Lined by [%s] - %s",
				me.name, source_p->name, name, 
				aconf->name, aconf->passwd);
		return;
	}

	apply_xline(source_p, name, reason, temp_time);
}

/* valid_xline()
 *
 * inputs	- client xlining, gecos, reason and whether to warn
 * outputs	-
 * side effects - checks the xline for validity, erroring if needed
 */
static int
valid_xline(struct Client *source_p, const char *gecos,
	    const char *reason,  int temp_time)
{
	if(EmptyString(reason))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   get_id(&me, source_p), 
			   get_id(source_p, source_p), "XLINE");
		return 0;
	}

	if(strchr(reason, ':') != NULL)
	{
		sendto_one_notice(source_p,
				  ":Invalid character ':' in comment");
		return 0;
	}

	if(strchr(reason, '"'))
	{
		sendto_one_notice(source_p,
				":Invalid character '\"' in comment");
		return 0;
	}

	if(!valid_wild_card_simple(gecos))
	{
		sendto_one_notice(source_p,
				  ":Please include at least %d non-wildcard "
				  "characters with the xline",
				  ConfigFileEntry.min_nonwildcard_simple);
		return 0;
	}

	/* The following test checks for an xline which would break the
	 * parser (which doesnt understand quoting).
	 *
	 * We dont lose much here, permanent versions of these would break
	 * the parser on a reload anyway. --anfl
	 */
	if(!temp_time && strstr(gecos, "\","))
	{
		sendto_one_notice(source_p,
				":Xlines containing \", must be temporary.");
		return 0;
	}

	return 1;
}

void
apply_xline(struct Client *source_p, const char *name, const char *reason,
		int temp_time)
{
	struct ConfItem *aconf;

	aconf = make_conf();
	aconf->status = CONF_XLINE;

	if(strstr(name, "\\s"))
	{
		char *tmp = LOCAL_COPY(name);
		char *orig = tmp;
		char *new = tmp;

		while(*orig)
		{
			if(*orig == '\\' && *(orig + 1) != '\0')
			{
				if(*(orig + 1) == 's')
				{
					*new++ = ' ';
					orig += 2;
				}
				/* otherwise skip that and the escaped
				 * character after it, so we dont mistake
				 * \\s as \s --fl
				 */
				else
				{
					*new++ = *orig++;
					*new++ = *orig++;
				}
			}
			else
				*new++ = *orig++;
		}

		*new = '\0';
		DupString(aconf->name, tmp);
	}
	else
		DupString(aconf->name, name);

	DupString(aconf->passwd, reason);
	collapse(aconf->name);

	if(temp_time > 0)
	{
		aconf->hold = CurrentTime + temp_time;

		sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s added temporary %d min. X-Line for [%s] [%s]",
			     get_oper_name(source_p), temp_time / 60,
			     aconf->name, reason);
		ilog(L_KLINE, "X %s %d %s %s",
			get_oper_name(source_p), temp_time / 60,
			name, reason);
		sendto_one_notice(source_p, ":Added temporary %d min. X-Line [%s]",
				temp_time / 60, aconf->name);
	}
	else
	{
		write_xline(source_p, aconf);

		sendto_realops_flags(UMODE_ALL, L_ALL, "%s added X-Line for [%s] [%s]",
				get_oper_name(source_p), 
				aconf->name, aconf->passwd);
		sendto_one_notice(source_p, ":Added X-Line for [%s] [%s]",
					aconf->name, aconf->passwd);
		ilog(L_KLINE, "X %s 0 %s %s",
			get_oper_name(source_p), name, reason);
	}

	dlinkAddAlloc(aconf, &xline_conf_list);
	check_xlines();
}

/* write_xline()
 *
 * inputs	- gecos, reason, xline type
 * outputs	- writes an xline to the config
 * side effects - 
 */
static void
write_xline(struct Client *source_p, struct ConfItem *aconf)
{
	char buffer[BUFSIZE * 2];
	FILE *out;
	const char *filename;

	filename = ConfigFileEntry.xlinefile;

	if((out = fopen(filename, "a")) == NULL)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "*** Problem opening %s ", filename);
		free_conf(aconf);
		return;
	}

	ircsprintf(buffer, "\"%s\",\"0\",\"%s\",\"%s\",%ld\n",
		   aconf->name, aconf->passwd,
		   get_oper_name(source_p), CurrentTime);

	if(fputs(buffer, out) == -1)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "*** Problem writing to %s", filename);
		free_conf(aconf);
		fclose(out);
		return;
	}

	fclose(out);
}

static void 
propagate_xline(struct Client *source_p, const char *target,
		int temp_time, const char *name, const char *type,
		const char *reason)
{
	if(!temp_time)
	{
		sendto_match_servs(source_p, target, CAP_CLUSTER, NOCAPS,
					"XLINE %s %s %s :%s",
					target, name, type, reason);
		sendto_match_servs(source_p, target, CAP_ENCAP, CAP_CLUSTER,
				"ENCAP %s XLINE %d %s 2 :%s",
				target, temp_time, name, reason);
	}
	else
		sendto_match_servs(source_p, target, CAP_ENCAP, NOCAPS,
				"ENCAP %s XLINE %d %s %s :%s",
				target, temp_time, name, type, reason);
}
			
static void
cluster_xline(struct Client *source_p, int temp_time, const char *name,
		const char *reason)
{
	struct remote_conf *shared_p;
	dlink_node *ptr;

	DLINK_FOREACH(ptr, cluster_conf_list.head)
	{
		shared_p = ptr->data;

		/* old protocol cant handle temps, and we dont really want
		 * to convert them to perm.. --fl
		 */
		if(!temp_time)
		{
			if(!(shared_p->flags & SHARED_PXLINE))
				continue;

			sendto_match_servs(source_p, shared_p->server, CAP_CLUSTER, NOCAPS,
					"XLINE %s %s 2 :%s",
					shared_p->server, name, reason);
			sendto_match_servs(source_p, shared_p->server, CAP_ENCAP, CAP_CLUSTER,
					"ENCAP %s XLINE 0 %s 2 :%s",
					shared_p->server, name, reason);
		}
		else if(shared_p->flags & SHARED_TXLINE)
			sendto_match_servs(source_p, shared_p->server, CAP_ENCAP, NOCAPS,
					"ENCAP %s XLINE %d %s 2 :%s",
					shared_p->server, temp_time, name, reason);
	}
}

/* mo_unxline()
 *
 * parv[1] - thing to unxline
 */
static int
mo_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS),
			   me.name, source_p->name, "xline");
		return 0;
	}

	if(parc == 4 && !(irccmp(parv[2], "ON")))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				me.name, source_p->name, "remoteban");
			return 0;
		}

		propagate_generic(source_p, "UNXLINE", parv[3], CAP_CLUSTER,
				"%s", parv[1]);

		if(match(parv[3], me.name) == 0)
			return 0;
	}
	else if(dlink_list_length(&cluster_conf_list))
		cluster_generic(source_p, "UNXLINE", SHARED_UNXLINE, CAP_CLUSTER,
				"%s", parv[1]);

	if(remove_temp_xline(source_p, parv[1]))
		return 0;

	remove_xline(source_p, parv[1]);

	return 0;
}

/* ms_unxline()
 *
 * handles a remote unxline
 */
static int
ms_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* parv[0]  parv[1]        parv[2]
	 * oper     target server  gecos
	 */
	propagate_generic(source_p, "UNXLINE", parv[1], CAP_CLUSTER,
			"%s", parv[2]);

	if(!match(parv[1], me.name))
		return 0;

	if(!IsPerson(source_p))
		return 0;

	handle_remote_unxline(source_p, parv[2]);
	return 0;
}

static int
me_unxline(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* name */
	if(!IsPerson(source_p))
		return 0;

	handle_remote_unxline(source_p, parv[1]);
	return 0;
}

static void
handle_remote_unxline(struct Client *source_p, const char *name)
{
	if(!find_shared_conf(source_p->username, source_p->host,
				source_p->servptr->name, SHARED_UNXLINE))
		return;

	if(remove_temp_xline(source_p, name))
		return;

	remove_xline(source_p, name);

	return;
}

static int
remove_temp_xline(struct Client *source_p, const char *name)
{
	struct ConfItem *aconf;
	dlink_node *ptr;

	DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		/* only want to check temp ones! */
		if(!aconf->hold)
			continue;

		if(!irccmp(aconf->name, name))
		{
			sendto_one_notice(source_p, 
					":X-Line for [%s] is removed",
					name);
			sendto_realops_flags(UMODE_ALL, L_ALL,
					 "%s has removed the temporary X-Line for: [%s]",
					 get_oper_name(source_p), name);
			ilog(L_KLINE, "UX %s %s", 
				get_oper_name(source_p), name);
			
			free_conf(aconf);
			dlinkDestroy(ptr, &xline_conf_list);
			return 1;
		}
	}

	return 0;
}

/* remove_xline()
 *
 * inputs	- gecos to remove
 * outputs	- 
 * side effects - removes xline from conf, if exists
 */
static void
remove_xline(struct Client *source_p, const char *huntgecos)
{
	FILE *in, *out;
	char buf[BUFSIZE];
	char buff[BUFSIZE];
	char temppath[BUFSIZE];
	const char *filename;
	const char *gecos;
	mode_t oldumask;
	char *p;
	int error_on_write = 0;
	int found_xline = 0;

	filename = ConfigFileEntry.xlinefile;
	ircsnprintf(temppath, sizeof(temppath),
		 "%s.tmp", ConfigFileEntry.xlinefile);

	if((in = fopen(filename, "r")) == NULL)
	{
		sendto_one_notice(source_p, ":Cannot open %s", filename);
		return;
	}

	oldumask = umask(0);

	if((out = fopen(temppath, "w")) == NULL)
	{
		sendto_one_notice(source_p, ":Cannot open %s", temppath);
		fclose(in);
		umask(oldumask);
		return;
	}

	umask(oldumask);

	while (fgets(buf, sizeof(buf), in))
	{
		if(error_on_write)
		{
			if(temppath != NULL)
				(void) unlink(temppath);

			break;
		}

		strlcpy(buff, buf, sizeof(buff));

		if((p = strchr(buff, '\n')) != NULL)
			*p = '\0';

		if((*buff == '\0') || (*buff == '#'))
		{
			error_on_write = (fputs(buf, out) < 0) ? YES : NO;
			continue;
		}

		if((gecos = getfield(buff)) == NULL)
		{
			error_on_write = (fputs(buf, out) < 0) ? YES : NO;
			continue;
		}

		/* matching.. */
		if(irccmp(gecos, huntgecos) == 0)
			found_xline++;
		else
			error_on_write = (fputs(buf, out) < 0) ? YES : NO;
	}

	fclose(in);
	fclose(out);

	if(error_on_write)
	{
		sendto_one_notice(source_p,
				  ":Couldn't write temp xline file, aborted");
		return;
	}
	else if(found_xline == 0)
	{
		sendto_one_notice(source_p, ":No X-Line for %s", huntgecos);

		if(temppath != NULL)
			(void) unlink(temppath);
		return;
	}

	(void) rename(temppath, filename);
	rehash_bans(0);

	sendto_one_notice(source_p, ":X-Line for [%s] is removed", huntgecos);
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "%s has removed the X-Line for: [%s]",
			     get_oper_name(source_p), huntgecos);
	ilog(L_KLINE, "UX %s %s", get_oper_name(source_p), huntgecos);
}
