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

#include "modules.h"		/* includes msg.h; use for the msgtab */

#include "handlers.h"		/* m_ignore */

#include "hash.h"		/* find_client and hash_find_channel */

#include "irc_string.h"		/* strlen */

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
static void me_authflags(struct Client *, struct Client *, int, char *[]);


/*
 * Show the commands this module can handle in a msgtab
 * and give the msgtab a name, here its samode_msgtab
 */
struct Message authflags_msgtab = {

	"AUTHFLAGS", 0, 0, 2, 0, MFLG_SLOW, 0,
	{m_ignore, m_ignore, m_ignore, me_authflags, m_ignore, m_ignore}
};

/* That's the msgtab finished */

#ifndef STATIC_MODULES
void
_modinit(void)
{
	/* This will add the commands in samode_msgtab (which is above) */
	mod_add_cmd(&authflags_msgtab);
}

void
_moddeinit(void)
{
	/* This will remove the commands in samode_msgtab (which is above) */
	mod_del_cmd(&authflags_msgtab);
}

const char *_version = "$Revision: 1.0 $";
#endif

/*
 * set_user_authflags
 *      target_p = client for whom we set flags
 *      flags = flags to set
 */
void
set_user_authflags(struct Client *target_p, char *flags)
{
	int i;
	
	for(i = 0; i<strlen(flags); i++)
	{
		switch(*(flags+i)) { 
			case '$':
				SetExemptResv(target_p);
				break;
			case '=':
				SetIPSpoof(target_p);
				break;
			case '^':
				SetExemptKline(target_p);
				break;
			case '_':
				SetExemptGline(target_p);
				break;
			case '>':
				SetExemptLimits(target_p);
				break;
			case '<':
				SetIdlelined(target_p);
				break;
			case '|':
				SetCanFlood(target_p);
				break;
			default:
				break;
    		}
	}
}

/*
 * me_authflags
 *      parv[0] = sender prefix
 *      parv[1] = parameter
 */
static void
me_authflags(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;

	if(!IsServer(source_p)) 
		return;

	if(parc < 3)
		return;

	if((target_p = (struct Client*)find_client(parv[1])) == NULL)
		return;


	if(!IsClient(target_p))
		return;

	set_user_authflags(target_p, parv[2]);
}


