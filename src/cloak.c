/*
 * ircd-hybrid: an advanced Internet Relay Chat Daemon (ircd).
 * cloak.c: Provides hostname (partial) cloaking for clients.
 *
 * Copyright (c) 2005 by the past and present ircd coders, and others.
 * Copyright (c) 2004 The UnrealIRCd Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at you option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILILTY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have recieved a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id: cloak.c 463 2006-12-25 05:50:02Z jon $
 */

#include "stdinc.h"
#include "whowas.h"
#include "channel_mode.h"
#include "client.h"
#include "common.h"
#include "hash.h"
#include "hook.h"
#include "irc_string.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "s_conf.h"
#include "modules.h"
#include "memory.h"
#include "s_log.h"
#include "sprintf_irc.h"
#include "cloak.h"

static char *cloak_key1 = NULL, *cloak_key2 = NULL, *cloak_key3 = NULL;

#undef KEY1
#undef KEY2
#undef KEY3
#define KEY1 cloak_key1
#define KEY2 cloak_key2
#define KEY3 cloak_key3

static char *hidehost(char *host);
static char *hidehost_ipv4(char *host);
static char *hidehost_ipv6(char *host);
static char *hidehost_normalhost(char *host);
static inline unsigned int downsample(char *i);

static int
check_badrandomness(char *key)
{
	char gotlowcase = 0, gotupcase = 0, gotdigit = 0;
	char *p;
	for(p = key; *p; p++)
		if(islower(*p))
			gotlowcase = 1;
		else if(isupper(*p))
			gotupcase = 1;
		else if(isdigit(*p))
			gotdigit = 1;

	if(gotlowcase && gotupcase && gotdigit)
		return 0;
	return 1;
}

void
init_cloak(void)
{
	int errors = 0;

	if(ConfigFileEntry.cloak_key1 == NULL)
	{
		ilog(L_CRIT, "cloak_key1 does not exist! Cloaking system has been disabled");
		return;
	}

	if(ConfigFileEntry.cloak_key2 == NULL)
	{
		ilog(L_CRIT, "cloak_key2 does not exist! Cloaking system has been disabled");
		return;
	}

	if(ConfigFileEntry.cloak_key3 == NULL)
	{
		ilog(L_CRIT, "cloak_key3 does not exist! Cloaking system has been disabled");
		return;
	}

	if(check_badrandomness(ConfigFileEntry.cloak_key1))
	{
		ilog(L_WARN,
		     "cloak_key1: Keys should be mixed a-zA-Z0-9, like \"a2JO6fh3Q6w4oN3s7\"");
		errors = 1;
	}

	if(check_badrandomness(ConfigFileEntry.cloak_key2))
	{
		ilog(L_WARN,
		     "cloak_key2: Keys should be mixed a-zA-Z0-9, like \"a2JO6fh3Q6w4oN3s7\"");
		errors = 1;
	}

	if(check_badrandomness(ConfigFileEntry.cloak_key3))
	{
		ilog(L_WARN,
		     "cloak_key3: Keys should be mixed a-zA-Z0-9, like \"a2JO6fh3Q6w4oN3s7\"");
		errors = 1;
	}

	if((strlen(ConfigFileEntry.cloak_key1) < 5) || (strlen(ConfigFileEntry.cloak_key1) > 100))
	{
		ilog(L_WARN,
		     "cloak_key1: Each key should be at least 5 characters, and no longer than 100");
		errors = 1;
	}

	if((strlen(ConfigFileEntry.cloak_key2) < 5) || (strlen(ConfigFileEntry.cloak_key2) > 100))
	{
		ilog(L_WARN,
		     "cloak_key2: Each key should be at least 5 characters, and no longer than 100");
		errors = 1;
	}

	if((strlen(ConfigFileEntry.cloak_key3) < 5) || (strlen(ConfigFileEntry.cloak_key3) > 100))
	{
		ilog(L_WARN,
		     "cloak_key3: Each key should be at least 5 characters, and no longer than 100");
		errors = 1;
	}

	if(!strcmp(ConfigFileEntry.cloak_key1, ConfigFileEntry.cloak_key2)
	   || !strcmp(ConfigFileEntry.cloak_key2, ConfigFileEntry.cloak_key3))
	{
		ilog(L_WARN, "All your 3 keys should be RANDOM, they should not be equal");
		errors = 1;
	}

	if(errors > 0)
	{
		ilog(L_CRIT,
		     "There were errors with your cloak keys. The cloaking system has been disabled");
		ConfigFileEntry.enable_cloak_system = NO;
		return;
	}
	else
	{
		cloak_key1 = strdup(ConfigFileEntry.cloak_key1);
		cloak_key2 = strdup(ConfigFileEntry.cloak_key2);
		cloak_key3 = strdup(ConfigFileEntry.cloak_key3);
		ConfigFileEntry.enable_cloak_system = YES;
		return;
	}
}

static char *
hidehost(char *host)
{
	char *p;

	/* IPv6 ? */
	if(strchr(host, ':'))
		return hidehost_ipv6(host);

	/* Is this a IPv4 IP? */
	for(p = host; *p; p++)
		if(!isdigit(*p) && !(*p == '.'))
			break;
	if(!(*p))
		return hidehost_ipv4(host);

	/* Normal host */
	return hidehost_normalhost(host);
}

/** Downsamples a 128bit result to 32bits (md5 -> unsigned int) */
static inline unsigned int
downsample(char *i)
{
	char r[4];

	r[0] = i[0] ^ i[1] ^ i[2] ^ i[3];
	r[1] = i[4] ^ i[5] ^ i[6] ^ i[7];
	r[2] = i[8] ^ i[9] ^ i[10] ^ i[11];
	r[3] = i[12] ^ i[13] ^ i[14] ^ i[15];

	return (((unsigned int) r[0] << 24) +
		((unsigned int) r[1] << 16) + ((unsigned int) r[2] << 8) + (unsigned int) r[3]);
}

static char *
hidehost_ipv4(char *host)
{
	unsigned int a, b, c, d;
	static char buf[512], res[512], res2[512], result[128];
	unsigned long n;
	unsigned int alpha, beta, gamma;

	/* 
	 * Output: ALPHA.BETA.GAMMA.IP
	 * ALPHA is unique for a.b.c.d
	 * BETA  is unique for a.b.c.*
	 * GAMMA is unique for a.b.*
	 * We cloak like this:
	 * ALPHA = downsample(md5(md5("KEY2:A.B.C.D:KEY3")+"KEY1"));
	 * BETA  = downsample(md5(md5("KEY3:A.B.C:KEY1")+"KEY2"));
	 * GAMMA = downsample(md5(md5("KEY1:A.B:KEY2")+"KEY3"));
	 */
	sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);

	/* ALPHA... */
	ircsprintf(buf, "%s:%s:%s", KEY2, host, KEY3);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY1);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	alpha = downsample(res2);

	/* BETA... */
	ircsprintf(buf, "%s:%d.%d.%d:%s", KEY3, a, b, c, KEY1);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY2);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	beta = downsample(res2);

	/* GAMMA... */
	ircsprintf(buf, "%s:%d.%d:%s", KEY1, a, b, KEY2);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY3);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	gamma = downsample(res2);

	ircsprintf(result, "%X.%X.%X.IP", alpha, beta, gamma);
	return result;
}

static char *
hidehost_ipv6(char *host)
{
	unsigned int a, b, c, d, e, f, g, h;
	static char buf[512], res[512], res2[512], result[128];
	unsigned long n;
	unsigned int alpha, beta, gamma;

	/* 
	 * Output: ALPHA:BETA:GAMMA:IP
	 * ALPHA is unique for a:b:c:d:e:f:g:h
	 * BETA  is unique for a:b:c:d:e:f:g
	 * GAMMA is unique for a:b:c:d
	 * We cloak like this:
	 * ALPHA = downsample(md5(md5("KEY2:a:b:c:d:e:f:g:h:KEY3")+"KEY1"));
	 * BETA  = downsample(md5(md5("KEY3:a:b:c:d:e:f:g:KEY1")+"KEY2"));
	 * GAMMA = downsample(md5(md5("KEY1:a:b:c:d:KEY2")+"KEY3"));
	 */
	sscanf(host, "%x:%x:%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f, &g, &h);

	/* ALPHA... */
	ircsprintf(buf, "%s:%s:%s", KEY2, host, KEY3);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY1);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	alpha = downsample(res2);

	/* BETA... */
	ircsprintf(buf, "%s:%x:%x:%x:%x:%x:%x:%x:%s", KEY3, a, b, c, d, e, f, g, KEY1);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY2);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	beta = downsample(res2);

	/* GAMMA... */
	ircsprintf(buf, "%s:%x:%x:%x:%x:%s", KEY1, a, b, c, d, KEY2);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY3);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	gamma = downsample(res2);

	ircsprintf(result, "%X:%X:%X:IP", alpha, beta, gamma);
	return result;
}

static char *
hidehost_normalhost(char *host)
{
	char *p;
	static char buf[512], res[512], res2[512], result[HOSTLEN + 1];
	unsigned int alpha, n;

	ircsprintf(buf, "%s:%s:%s", KEY1, host, KEY2);
	DoMD5(res, buf, strlen(buf));
	strcpy(res + 16, KEY3);	/* first 16 bytes are filled, append our key.. */
	n = strlen(res + 16) + 16;
	DoMD5(res2, res, n);
	alpha = downsample(res2);

	for(p = host; *p; p++)
		if(*p == '.')
			if(isalpha(*(p + 1)))
				break;

	if(*p)
	{
		unsigned int len;
		p++;
		ircsprintf(result, "%s-%X.", ServerInfo.network_name, alpha);
		len = strlen(result) + strlen(p);
		if(len <= HOSTLEN)
			strcat(result, p);
		else
			strcat(result, p + (len - HOSTLEN));
	}
	else
		ircsprintf(result, "%s-%X", ServerInfo.network_name, alpha);

	return result;
}

char *
make_virthost(char *curr, char *new)
{
	char host[256], *mask, *p, *q;

	if(!curr)
		return NULL;

	/* Convert host to lowercase and cut off at 255 bytes just to be sure */
	for(p = curr, q = host; *p && (q < host + sizeof(host) - 1); p++, q++)
		*q = tolower(*p);
	*q = '\0';

	mask = hidehost(host);

	strlcpy(new, mask, HOSTLEN + 1);

	return NULL;
}
