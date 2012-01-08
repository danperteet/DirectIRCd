/* $Id: s_cloaking.c 257 2007-04-01 12:53:21Z jilles $ */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"

static int
_modinit(void)
{
	/* add the usermode to the available slot */
	user_modes['m'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	/* disable the umode and remove it from the available list */
	user_modes['m'] = 0;
	construct_umodebuf();
}

static int mo_showmask(struct Client *, struct Client *, int, const char **);
struct Message showmask_msgtab = {
	"SHOWMASK", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_showmask, 2}}
};

mapi_clist_av1 ip_cloaking_clist[] = { &showmask_msgtab, NULL };

static void check_umode_change(void *data);
static void check_new_user(void *vdata);
mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{"umode_changed", (hookfn) check_umode_change},
	{"new_local_user", (hookfn) check_new_user},
	{NULL, NULL}
};

DECLARE_MODULE_AV1(ip_cloaking, _modinit, _moddeinit, ip_cloaking_clist, NULL,
		   ip_cloaking_hfnlist, "$Revision: 257 $");

static void
distribute_hostchange(struct Client *client)
{
	if(irccmp(client->host, client->orighost))
		sendto_one_numeric(client, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				   client->host);
	else
		sendto_one_numeric(client, RPL_HOSTHIDDEN, "%s :hostname reset",
				   client->host);

	sendto_server(NULL, NULL,
		      CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		      use_id(&me), use_id(client), client->host);
	sendto_server(NULL, NULL,
		      CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		      use_id(&me), use_id(client), client->host);
	sendto_server(NULL, NULL,
		      NOCAPS, CAP_TS6, ":%s ENCAP * CHGHOST %s :%s",
		      me.name, client->name, client->host);
	if(irccmp(client->host, client->orighost))
		SetDynSpoof(client);
	else
		ClearDynSpoof(client);
}

/*
 * MD5 transform algorithm, taken from code written by Colin Plumb,
 * and put into the public domain
 *
 * QUESTION: Replace this with SHA, which as generally received better
 * reviews from the cryptographic community?
 */
void
ircd_MD5Init(uint32_t buf[4])
{
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.
 */
void
ircd_MD5Transform(uint32_t buf[4], uint32_t in[16])
{
	uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[ 0]+0xd76aa478,  7);
	MD5STEP(F1, d, a, b, c, in[ 1]+0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[ 2]+0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[ 3]+0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[ 4]+0xf57c0faf,  7);
	MD5STEP(F1, d, a, b, c, in[ 5]+0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[ 6]+0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[ 7]+0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[ 8]+0x698098d8,  7);
	MD5STEP(F1, d, a, b, c, in[ 9]+0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10]+0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11]+0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12]+0x6b901122,  7);
	MD5STEP(F1, d, a, b, c, in[13]+0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14]+0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15]+0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[ 1]+0xf61e2562,  5);
	MD5STEP(F2, d, a, b, c, in[ 6]+0xc040b340,  9);
	MD5STEP(F2, c, d, a, b, in[11]+0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[ 0]+0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[ 5]+0xd62f105d,  5);
	MD5STEP(F2, d, a, b, c, in[10]+0x02441453,  9);
	MD5STEP(F2, c, d, a, b, in[15]+0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[ 4]+0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[ 9]+0x21e1cde6,  5);
	MD5STEP(F2, d, a, b, c, in[14]+0xc33707d6,  9);
	MD5STEP(F2, c, d, a, b, in[ 3]+0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[ 8]+0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13]+0xa9e3e905,  5);
	MD5STEP(F2, d, a, b, c, in[ 2]+0xfcefa3f8,  9);
	MD5STEP(F2, c, d, a, b, in[ 7]+0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12]+0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[ 5]+0xfffa3942,  4);
	MD5STEP(F3, d, a, b, c, in[ 8]+0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11]+0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14]+0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[ 1]+0xa4beea44,  4);
	MD5STEP(F3, d, a, b, c, in[ 4]+0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[ 7]+0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10]+0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13]+0x289b7ec6,  4);
	MD5STEP(F3, d, a, b, c, in[ 0]+0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[ 3]+0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[ 6]+0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[ 9]+0xd9d4d039,  4);
	MD5STEP(F3, d, a, b, c, in[12]+0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15]+0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[ 2]+0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[ 0]+0xf4292244,  6);
	MD5STEP(F4, d, a, b, c, in[ 7]+0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14]+0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[ 5]+0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12]+0x655b59c3,  6);
	MD5STEP(F4, d, a, b, c, in[ 3]+0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10]+0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[ 1]+0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[ 8]+0x6fa87e4f,  6);
	MD5STEP(F4, d, a, b, c, in[15]+0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[ 6]+0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13]+0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[ 4]+0xf7537e82,  6);
	MD5STEP(F4, d, a, b, c, in[11]+0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[ 2]+0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[ 9]+0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

int
ip6TokPut(char *s, int n)
{
	const char tb[] = "zvpd63g8x7omwb1yecrfl2qs9h4t0j5anuk";
	int i = 0;

	while(n > (sizeof tb))
	{
		s[i++] = tb[n % ((sizeof tb) - 1)];
		n /= ((sizeof tb) - 1);
	}

	s[i++] = tb[n % ((sizeof tb) - 1)];
	return i;
}

char *
tokenEncode(const char *str)
{
	static char strn[HOSTLEN + 255];
	const unsigned char *p;
	uint32_t v;

	v = 0x55555;
	for(p = (const unsigned char *)str; *p; p++)
		v = (31 * v) + (*p);
	sprintf(strn, "%x", v);
	return strn;
}

const char *
genHostMask(const char *host)
{
	char tok1[USERLEN + HOSTLEN + 255];
	char tok2[USERLEN + HOSTLEN + 255];
	const char *p;
	char *q, *qq;
	static char fin[USERLEN + HOSTLEN + 255];
	char fintmp[USERLEN + HOSTLEN + 255];
	int i, fIp = TRUE;
	char hostcopy[HOSTLEN + 1];

	if(!host || strlen(host) > HOSTLEN)
		return (host ? host : "");
	rb_strlcpy(hostcopy, host, sizeof hostcopy);

	if(strchr(host, ':'))
	{
		/* ipv6 address */
		uint32_t md5data[16];
		static uint32_t md5hash[4];
		int k, x[8] = { }, j, dcolon = -1;
		char *s;

		strcpy(tok2, host);
		tok1[0] = '\0';
		k = 0;

		for(k = 0, p = host; *p != '\0';)
		{
			x[k++] = (short int) strtol(p, &s, 16);
			if(s == p)
			{
				if(*p == ':')
					dcolon = k;
				else
					return (host ? host : "");
			}

			if(*s == '\0')
				break;
			if(*s != ':')
				return (host ? host : "");
			if(k > 7)
				return (host ? host : "");
			p = s + 1;
		}

		if(k < 8 && dcolon != -1)
		{
			for (j = 0; j < k - dcolon; j++)
				x[7 - j] = x[k - j - 1];
			for (; j <= 7 - dcolon; j++)
				x[7 - j] = 0;
			k = 8;
		}
		if(k != 8)
			return (host ? host : "");

		memset(md5data, 0, sizeof(md5data));
		md5data[0] = x[0];
		md5data[2] = x[1];
		md5data[4] = x[2];

		md5data[1] = '6';
		md5data[3] = 0x6f1553bc;
		md5data[5] = 0x7ef01c9e;
		md5data[7] = 0x606b909f;
		md5data[9] = 0x9495742e;
		md5data[11] = 0xe8f50e06;
		md5data[13] = 0xd7b58f7f;
		md5data[15] = 0x4c27d776;

		/*for(k = 0, j = 0; k < 16; k += 2, j++)
			md5data[k] = x[j];*/

		/* hash of first 48 bits */
		ircd_MD5Init(md5hash);
		ircd_MD5Transform(md5hash, md5data);
		k = ip6TokPut(tok1, md5hash[0]);
		tok1[k] = '\0';

		/* hash of first 64 bits */
		md5data[6] = x[3];
		ircd_MD5Init(md5hash);
		ircd_MD5Transform(md5hash, md5data);
		k = ip6TokPut(tok2, md5hash[1]);
		tok2[k] = '\0';

		/* hash of everything */
		md5data[8] = x[4];
		md5data[10] = x[5];
		md5data[12] = x[6];
		md5data[14] = x[7];
		ircd_MD5Init(md5hash);
		ircd_MD5Transform(md5hash, md5data);
		k = ip6TokPut(fin, md5hash[2]);
		k += ip6TokPut(fin + k, md5hash[3]);

		sprintf(fin + k, ".%s.%s.%04x%04x.ipv6", tok2, tok1, x[0] & 0xffff, x[1] & 0xffff);
		return fin;
	}

	if(!strchr(host, '.'))
		return (host ? host : "");
	for(i = 0; host[i]; i++)
		if((host[i] < '0' || host[i] > '9') && host[i] != '.')
		{
			fIp = FALSE;
			break;
		}

	*tok1 = *tok2 = '\0';

	/* It's an ipv4 address in quad-octet format: last two tokens are encoded */
	if(fIp && strlen(host) <= 15)
	{
		if((q = strrchr(hostcopy, '.')))
		{
			*q = '\0';
			strcpy(tok1, hostcopy);
			strcpy(tok2, q + 1);
			*q = '.';
		}
		if((q = strrchr(tok1, '.')))
		{
			strcpy(fintmp, tokenEncode(q + 1));
			*q = '\0';
		}
		sprintf(fin, "%s.%s.%s.imsk", tokenEncode(tok2), fintmp, tok1);
		return fin;
	}

	/* It's a resolved hostname, hash the first token */
	if((q = strchr(hostcopy, '.')))
	{
		*q = '\0';
		strcpy(tok1, hostcopy);
		strcpy(fin, q + 1);
		*q = '.';
	}

	/* Then separately hash the domain */
	if((q = strrchr(fin, '.')))
	{
		--q;
		while(q > fin && *(q - 1) != '.')
			q--;
	}
	if(q && (qq = strrchr(fin, '.')))
	{
		i = (unsigned char) *q;
		*q = '\0';
		*qq = '\0';
		strcat(tok2, fin);
		*q = (unsigned char) i;
		if(*q == '.')
			strcat(tok2, tokenEncode(q + 1));
		else
			strcat(tok2, tokenEncode(q));
		*qq = '.';
		strcat(tok2, qq);
	}
	else
		strcpy(tok2, fin);
	strcpy(tok1, tokenEncode(tok1));
	snprintf(fin, HOSTLEN, "%s.%s.hmsk", tok1, tok2);

	return fin;
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *) vdata;
	struct Client *source_p = data->client;

	if(!MyClient(source_p))
		return;

	/* didn't change +h umode, we don't need to do anything */
	if(!((data->oldumodes ^ source_p->umodes) & user_modes['m']))
		return;

	if((source_p->umodes & user_modes['m']) && !irccmp(source_p->orighost, source_p->host))
	{
		if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL || (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['m'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			rb_strlcpy(source_p->host, source_p->localClient->mangledhost, HOSTLEN);
			distribute_hostchange(source_p);
		}
		else
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				source_p->host);
	}
	else if(!(source_p->umodes & user_modes['m']) && irccmp(source_p->orighost, source_p->host))
	{
		if (source_p->localClient->mangledhost != NULL &&
				!strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			rb_strlcpy(source_p->host, source_p->orighost, HOSTLEN);
			distribute_hostchange(source_p);
		}
	}
}

static void
check_new_user(void *vdata)
{
        struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['m'];
		return;
	}
	source_p->localClient->mangledhost = rb_strdup(genHostMask(source_p->orighost));
	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['m'];
	if (source_p->umodes & user_modes['m'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost, HOSTLEN);
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}

static int mo_showmask(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (strlen(parv[1]) > HOSTLEN)
		sendto_one_notice(source_p, ":Invalid parameters");
	else
		sendto_one_notice(source_p, ":%25s -> %25s", parv[1],
				genHostMask(parv[1]));
	return 0;
}

