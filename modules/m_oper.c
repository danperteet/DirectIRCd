/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_oper.c: Makes a user an IRC Operator.
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
 *  $Id: m_oper.c 22407 2006-05-07 15:39:43Z androsyn $
 */

#include "stdinc.h"

#ifdef HAVE_LIBCRYPTO
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "tools.h"
#include "client.h"
#include "common.h"
#include "irc_string.h"
#include "ircd.h"
#include "numeric.h"
#include "commio.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "s_user.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "packet.h"
#include "cache.h"

#define CHALLENGE_WIDTH BUFSIZE - (NICKLEN + HOSTLEN + 12)
#define CHALLENGE_EXPIRES	180	/* 180 seconds should be more than long enough */
#define CHALLENGE_SECRET_LENGTH	128	/* how long our challenge secret should be */

static int m_oper(struct Client *, struct Client *, int, const char **);
static int m_challenge(struct Client *, struct Client *, int, const char **);

struct Message oper_msgtab = {
	"OPER", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_oper, 3}, mg_ignore, mg_ignore, mg_ignore, {m_oper, 3}}
};
struct Message challenge_msgtab = {
	"CHALLENGE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_challenge, 2}, mg_ignore, mg_ignore, mg_ignore, {m_challenge, 2}}
};


mapi_clist_av1 oper_clist[] = { &oper_msgtab, &challenge_msgtab, NULL };
DECLARE_MODULE_AV1(oper, NULL, NULL, oper_clist, NULL, NULL, "$Revision: 22407 $");

static int match_oper_password(const char *password, struct oper_conf *oper_p);
extern char *crypt();

/*
 * m_oper
 *      parv[0] = sender prefix
 *      parv[1] = oper name
 *      parv[2] = oper password
 */
static int
m_oper(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct oper_conf *oper_p;
	const char *name;
	const char *password;

	name = parv[1];
	password = parv[2];

	if(IsOper(source_p))
	{
		sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
		send_oper_motd(source_p);
		return 0;
	}

	/* end the grace period */
	if(!IsFloodDone(source_p))
		flood_endgrace(source_p);

	oper_p = find_oper_conf(source_p->username, source_p->host, 
				source_p->sockhost, name);

	if(oper_p == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
		     name, source_p->name,
		     source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed OPER attempt - host mismatch by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}

		return 0;
	}

	if(match_oper_password(password, oper_p))
	{
		oper_up(source_p, oper_p);

		ilog(L_OPERED, "OPER %s by %s!%s@%s",
		     name, source_p->name, source_p->username, source_p->host);
		return 0;
	}
	else
	{
		sendto_one(source_p, form_str(ERR_PASSWDMISMATCH),
			   me.name, source_p->name);

		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
		     name, source_p->name, source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed OPER attempt by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		}
	}

	return 0;
}

/*
 * match_oper_password
 *
 * inputs       - pointer to given password
 *              - pointer to Conf 
 * output       - YES or NO if match
 * side effects - none
 */
static int
match_oper_password(const char *password, struct oper_conf *oper_p)
{
	const char *encr;

	/* passwd may be NULL pointer. Head it off at the pass... */
	if(EmptyString(oper_p->passwd))
		return NO;

	if(IsOperConfEncrypted(oper_p))
	{
		/* use first two chars of the password they send in as salt */
		/* If the password in the conf is MD5, and ircd is linked   
		 * to scrypt on FreeBSD, or the standard crypt library on
		 * glibc Linux, then this code will work fine on generating
		 * the proper encrypted hash for comparison.
		 */
		if(!EmptyString(password))
			encr = crypt(password, oper_p->passwd);
		else
			encr = "";
	}
	else
		encr = password;

	if(strcmp(encr, oper_p->passwd) == 0)
		return YES;
	else
		return NO;
}

#ifndef HAVE_LIBCRYPTO
static int
m_challenge(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	sendto_one(source_p, ":%s NOTICE %s :Challenge not implemented ",
		   me.name, source_p->name);
	return 0;
}

#else

static int generate_challenge(char **r_challenge, char **r_response, RSA * rsa);

static void
cleanup_challenge(struct Client *target_p)
{
	if(target_p->localClient == NULL)
		return;
	
	MyFree(target_p->localClient->challenge);
	MyFree(target_p->localClient->opername);
	target_p->localClient->challenge = NULL;
	target_p->localClient->opername = NULL;
	target_p->localClient->chal_time = 0;
}

/*
 * m_challenge - generate RSA challenge for wouldbe oper
 * parv[0] = sender prefix
 * parv[1] = operator to challenge for, or +response
 *
 */

static int
m_challenge(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct oper_conf *oper_p;
	char *challenge;
	char chal_line[CHALLENGE_WIDTH]; 
	unsigned char *b_response;
	size_t cnt;
	int len = 0;

	if(IsOper(source_p))
	{
		sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
		send_oper_motd(source_p);
		return 0;
	}

	if(*parv[1] == '+')
	{
		if(source_p->localClient->challenge == NULL)
			return 0;

		if((CurrentTime - source_p->localClient->chal_time) > CHALLENGE_EXPIRES)
		{
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);
			ilog(L_FOPER, "EXPIRED CHALLENGE (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Expired CHALLENGE attempt by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);
			cleanup_challenge(source_p);
			return 0;			
		}

		b_response = ircd_base64_decode((const unsigned char *)++parv[1], strlen(parv[1]), &len);

		if(len != SHA_DIGEST_LENGTH ||
		   memcmp(source_p->localClient->challenge, b_response, SHA_DIGEST_LENGTH))
		{
			sendto_one(source_p, form_str(ERR_PASSWDMISMATCH), me.name, source_p->name);
			ilog(L_FOPER, "FAILED CHALLENGE (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Failed CHALLENGE attempt by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);

			MyFree(b_response);
			cleanup_challenge(source_p);
			return 0;
		}

		MyFree(b_response);

		oper_p = find_oper_conf(source_p->username, source_p->host, 
					source_p->sockhost, 
					source_p->localClient->opername);

		if(oper_p == NULL)
		{
			sendto_one(source_p, form_str(ERR_NOOPERHOST), 
				   me.name, source_p->name);
			ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
			     source_p->localClient->opername, source_p->name,
			     source_p->username, source_p->host);

			if(ConfigFileEntry.failed_oper_notice)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Failed CHALLENGE attempt - host mismatch by %s (%s@%s)",
						     source_p->name, source_p->username,
						     source_p->host);
			return 0;
		}

		cleanup_challenge(source_p);

		oper_up(source_p, oper_p);

		ilog(L_OPERED, "OPER %s by %s!%s@%s",
		     source_p->localClient->opername, source_p->name, 
		     source_p->username, source_p->host);
		return 0;
	}

	cleanup_challenge(source_p);

	oper_p = find_oper_conf(source_p->username, source_p->host, 
				source_p->sockhost, parv[1]);

	if(oper_p == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOOPERHOST), me.name, source_p->name);
		ilog(L_FOPER, "FAILED OPER (%s) by (%s!%s@%s)",
		     parv[1], source_p->name,
		     source_p->username, source_p->host);

		if(ConfigFileEntry.failed_oper_notice)
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Failed CHALLENGE attempt - host mismatch by %s (%s@%s)",
					     source_p->name, source_p->username, source_p->host);
		return 0;
	}

	if(!oper_p->rsa_pubkey)
	{
		sendto_one(source_p, ":%s NOTICE %s :I'm sorry, PK authentication "
			   "is not enabled for your oper{} block.", me.name, parv[0]);
		return 0;
	}

	if(!generate_challenge(&challenge, &(source_p->localClient->challenge), oper_p->rsa_pubkey))
	{
		char *chal = challenge;
		source_p->localClient->chal_time = CurrentTime;
		for(;;)
		{
			cnt = strlcpy(chal_line, chal, CHALLENGE_WIDTH);
			sendto_one(source_p, form_str(RPL_RSACHALLENGE2), me.name, source_p->name, chal_line);
			if(cnt > CHALLENGE_WIDTH)
				chal += CHALLENGE_WIDTH - 1;
			else
				break;
			
		}
		sendto_one(source_p, form_str(RPL_ENDOFRSACHALLENGE2), 
			   me.name, source_p->name);
		MyFree(challenge);
		DupString(source_p->localClient->opername, oper_p->name);
	}
	else
		sendto_one_notice(source_p, ":Failed to generate challenge.");

	return 0;
}


static int
get_randomness(unsigned char *buf, int length)
{
	/* Seed OpenSSL PRNG with EGD enthropy pool -kre */
	if(ConfigFileEntry.use_egd && (ConfigFileEntry.egdpool_path != NULL))
	{
		if(RAND_egd(ConfigFileEntry.egdpool_path) == -1)
			return -1;
	}

	if(RAND_status())
	{
		if(RAND_bytes(buf, length) > 0)
			return 1;
	}
	else
	{
		if(RAND_pseudo_bytes(buf, length) >= 0)
			return 1;
	}
	return 0;
}

static int
generate_challenge(char **r_challenge, char **r_response, RSA * rsa)
{
	SHA_CTX ctx;
	unsigned char secret[CHALLENGE_SECRET_LENGTH], *tmp;
	unsigned long length;
	unsigned long e = 0;
	unsigned long cnt = 0;
	int ret;

	if(!rsa)
		return -1;
	if(get_randomness(secret, CHALLENGE_SECRET_LENGTH))
	{
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (uint8_t *)secret, CHALLENGE_SECRET_LENGTH);
		*r_response = MyMalloc(SHA_DIGEST_LENGTH);
		SHA1_Final((uint8_t *)*r_response, &ctx);

		length = RSA_size(rsa);
		tmp = MyMalloc(length);
		ret = RSA_public_encrypt(CHALLENGE_SECRET_LENGTH, secret, tmp, rsa, RSA_PKCS1_OAEP_PADDING);

		if (ret >= 0)
		{
			*r_challenge = (char *)ircd_base64_encode(tmp, ret);
			MyFree(tmp);
			return 0;
		}
		MyFree(tmp);
		MyFree(*r_response);
		*r_response = NULL;
	}

	ERR_load_crypto_strings();
	while ((cnt < 100) && (e = ERR_get_error()))
	{
		ilog(L_MAIN, "SSL error: %s", ERR_error_string(e, 0));
		cnt++;
	}

	return (-1);
}

#endif /* HAVE_LIBCRYPTO */
