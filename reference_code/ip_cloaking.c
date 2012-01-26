/* $Id$ */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "tools.h"
#include "numeric.h"

/* if you're modifying this module, you'll probably to change this */
#define KEY 0x13748cfa

static int
_modinit(void)
{
	/* add the usermode to the available slot */
	user_modes['h'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	/* disable the umode and remove it from the available list */
	user_modes['h'] = 0;
	construct_umodebuf();
}

static void check_umode_change(void *data);
mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(ip_cloaking, _modinit, _moddeinit, NULL, NULL,
			ip_cloaking_hfnlist, "$Revision$");

static void
distribute_hostchange(struct Client *client)
{
	if (irccmp(client->host, client->orighost))
	{
		sendto_one_numeric(client, RPL_HOSTHIDDEN, "%s :is now your hidden host",
			client->host);
	}

	sendto_server(NULL, NULL,
		CAP_TS6, NOCAPS, ":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client), client->host);
	sendto_server(NULL, NULL,
		NOCAPS, CAP_TS6, ":%s ENCAP * CHGHOST %s :%s",
		me.name, client->name, client->host);
	if (irccmp(client->host, client->orighost))
		SetDynSpoof(client);
	else
		ClearDynSpoof(client);
}

static void
do_host_cloak(const char *inbuf, char *outbuf, int ipmask)
{
	int cyc;
	unsigned int hosthash = 1, hosthash2 = 1;
	unsigned int maxcycle = strlen(inbuf); 	

	for (cyc = 0; cyc < maxcycle - 2; cyc += 2)
		hosthash *= (unsigned int) inbuf[cyc];

	/* safety: decrement ourselves two steps back */
	for (cyc = maxcycle - 1; cyc >= 1; cyc -= 2)
		hosthash2 *= (unsigned int) inbuf[cyc];

	/* lets do some bitshifting -- this pretty much destroys the IP
	 * sequence, while still providing a checksum. exactly what
	 * we're shooting for. --nenolod
	 */
	hosthash += (hosthash2 / KEY);
	hosthash2 += (hosthash / KEY);

	if (ipmask == 0)
		ircsnprintf(outbuf, HOSTLEN, "%s-%X%X%s",
			ServerInfo.network_name, hosthash2, hosthash, strchr(inbuf, '.'));
	else
		ircsnprintf(outbuf, HOSTLEN, "%X%X.%s",
			hosthash2, hosthash, ServerInfo.network_name);
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* didn't change +h umode, we don't need to do anything */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['h']))
		return;

	if ((source_p->umodes & user_modes['h']) &&
		!irccmp(source_p->orighost, source_p->host))
	{
		if (!irccmp(source_p->orighost, source_p->sockhost))
			do_host_cloak(source_p->orighost, source_p->host, 1);
		else
			do_host_cloak(source_p->orighost, source_p->host, 0);

		/* do cloaking here */
		distribute_hostchange(source_p);
	}
	else if (!(source_p->umodes & user_modes['h']) &&
		irccmp(source_p->orighost, source_p->host))
	{
		strlcpy(source_p->host, source_p->orighost, HOSTLEN);
		distribute_hostchange(source_p);
	}
}
