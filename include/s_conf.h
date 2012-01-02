/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_conf.h: A header for the configuration functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2004 ircd-ratbox development team
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
 *  $Id: s_conf.h 26234 2008-11-22 16:35:58Z androsyn $
 */

#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h
#include "setup.h"



#ifdef HAVE_LIBCRYPTO
#include <openssl/rsa.h>
#endif

#include "ircd_defs.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "patricia.h"

struct Client;
struct DNSReply;
struct hostent;

/* used by new parser */
/* yacc/lex love globals!!! */

extern FILE *conf_fbfile_in;
extern char conf_line_in[256];

struct ConfItem
{
	unsigned int status;	/* If CONF_ILLEGAL, delete when no clients */
	unsigned int flags;
	int clients;		/* Number of *LOCAL* clients using this */
	char *name;		/* IRC name, nick, server name, or original u@h */
	char *host;		/* host part of user@host */
	char *passwd;		/* doubles as kline reason *ugh* */
	char *spasswd;		/* Password to send. */
	char *user;		/* user part of user@host */
	int port;
	time_t hold;		/* Hold action until this time (calendar time) */
	struct Class *c_class;	/* Class of connection */
};

/* CONF_SKIPUSER is used solely in hostmask.c and never applied to a struct
 * ConfItem.  It signals to the lookup code that a match() on the username
 * will always return true -- notably because its empty or "*".  This allows
 * us to fall back to a bitmask test, instead of jumping into match().
 *
 * EFNet profiling showed that match() was called 937million times from
 * hostmask.c, making it the most used function by a huge factor.  The sheer
 * number of calls makes this special case worthwhile.
 *
 * Its a Good Idea. --fl
 */
#define CONF_SKIPUSER		0x0001
#define CONF_CLIENT             0x0002
#define CONF_KILL               0x0040
#define CONF_XLINE		0x0080
#define CONF_RESV_CHANNEL	0x0100
#define CONF_RESV_NICK		0x0200
#define CONF_RESV		(CONF_RESV_CHANNEL | CONF_RESV_NICK)

#define CONF_GLINE             0x10000
#define CONF_DLINE             0x20000
#define CONF_EXEMPTDLINE      0x100000

#define CONF_ILLEGAL            0x80000000

#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/* aConfItem->flags */

/* Generic flags... */
/* access flags... */
#define CONF_FLAGS_NO_TILDE             0x00000004
#define CONF_FLAGS_NEED_IDENTD          0x00000008
#define CONF_FLAGS_EXEMPTKLINE          0x00000040
#define CONF_FLAGS_NOLIMIT              0x00000080
#define CONF_FLAGS_SPOOF_IP             0x00000200
#define CONF_FLAGS_SPOOF_NOTICE		0x00000400
#define CONF_FLAGS_REDIR                0x00000800
#define CONF_FLAGS_EXEMPTGLINE          0x00001000
#define CONF_FLAGS_EXEMPTRESV		0x00002000	/* exempt from resvs */
#define CONF_FLAGS_EXEMPTFLOOD          0x00004000
#define CONF_FLAGS_EXEMPTSPAMBOT	0x00008000
#define CONF_FLAGS_EXEMPTSHIDE		0x00010000
#define CONF_FLAGS_EXEMPTJUPE		0x00020000	/* exempt from resv generating warnings */
/* server flags */
#define CONF_FLAGS_ENCRYPTED            0x00100000
#define CONF_FLAGS_TEMPORARY            0x00400000


/* Macros for struct ConfItem */
#define IsNoTilde(x)            ((x)->flags & CONF_FLAGS_NO_TILDE)
#define IsNeedIdentd(x)         ((x)->flags & CONF_FLAGS_NEED_IDENTD)
#define IsConfExemptKline(x)    ((x)->flags & CONF_FLAGS_EXEMPTKLINE)
#define IsConfExemptLimits(x)   ((x)->flags & CONF_FLAGS_NOLIMIT)
#define IsConfExemptGline(x)    ((x)->flags & CONF_FLAGS_EXEMPTGLINE)
#define IsConfExemptFlood(x)    ((x)->flags & CONF_FLAGS_EXEMPTFLOOD)
#define IsConfExemptSpambot(x)	((x)->flags & CONF_FLAGS_EXEMPTSPAMBOT)
#define IsConfExemptShide(x)	((x)->flags & CONF_FLAGS_EXEMPTSHIDE)
#define IsConfExemptJupe(x)	((x)->flags & CONF_FLAGS_EXEMPTJUPE)
#define IsConfExemptResv(x)	((x)->flags & CONF_FLAGS_EXEMPTRESV)
#define IsConfDoSpoofIp(x)      ((x)->flags & CONF_FLAGS_SPOOF_IP)
#define IsConfSpoofNotice(x)    ((x)->flags & CONF_FLAGS_SPOOF_NOTICE)
#define IsConfEncrypted(x)      ((x)->flags & CONF_FLAGS_ENCRYPTED)

/* flag definitions for opers now in client.h */

struct config_file_entry
{
	const char *dpath;	/* DPATH if set from command line */
	const char *configfile;
	const char *klinefile;
	const char *dlinefile;
	const char *xlinefile;
	const char *resvfile;

	char *servlink_path;
	char *egdpool_path;

	char *default_operstring;
	char *default_adminstring;
	char *kline_reason;
	
	char *fname_userlog;
	char *fname_fuserlog;
	char *fname_operlog;
	char *fname_foperlog;
	char *fname_serverlog;
	char *fname_killlog;
	char *fname_glinelog;
	char *fname_klinelog;
	char *fname_operspylog;
	char *fname_ioerrorlog;

	unsigned char compression_level;

	int anti_nick_flood;
	int anti_spam_exit_message_time;
	int burst_away;
	int caller_id_wait;
	int client_exit;
	int client_flood;
	int connect_timeout;
	int default_floodcount;
	int default_invisible;
	int disable_auth;
	int disable_fake_channels;
	int dline_with_reason;
	int dot_in_ip6_addr;
	int dots_in_ident;
	int failed_oper_notice;
	int glines;
	int gline_time;
	int gline_min_cidr;
	int gline_min_cidr6;
	int hide_server;
	int hide_spoof_ips;
	int hide_error_messages;
	int idletime;
	int kline_delay;
	int kline_with_reason;
	int map_oper_only;
	int max_accept;
	int max_monitor;
	int max_nick_time;
	int max_nick_changes;
	int max_targets;
	int min_nonwildcard;
	int min_nonwildcard_simple;
	int nick_delay;
	int no_oper_flood;
	int non_redundant_klines;
	int oper_only_umodes;
	int oper_umodes;
	int operspy_admin_only;
	int pace_wait;
	int pace_wait_simple;
	int ping_cookie;
	int reject_after_count;
	int reject_ban_time;
	int reject_duration;
	int short_motd;
	int stats_c_oper_only;
	int stats_e_disabled;
	int stats_h_oper_only;
	int stats_i_oper_only;
	int stats_k_oper_only;
	int stats_o_oper_only;
	int stats_P_oper_only;
	int stats_y_oper_only;
	int target_change;
	int tkline_expire_notices;
	int ts_max_delta;
	int ts_warn_delta;
	int use_egd;
	int use_whois_actually;
	int warn_no_nline;
	int max_unknown_ip;
};

struct config_channel_entry
{
	int burst_topicwho;
	int default_split_server_count;
	int default_split_user_count;
	int invite_ops_only;
	int knock_delay;
	int knock_delay_channel;
	int max_bans;
	int max_chans_per_user;
	int no_create_on_split;
	int no_join_on_split;
	int quiet_on_ban;
	int use_except;
	int use_invex;
	int use_knock;
};

struct config_server_hide
{
	int disable_hidden;
	int hidden;
	int flatten_links;
	int links_delay;
	int links_disabled;
};

struct server_info
{
	char *name;
	char sid[4];
	char *description;
	char *network_name;
	char *network_desc;
	int hub;
	int use_ts6;
	int default_max_clients;
	struct sockaddr_in ip;
#ifdef IPV6
	struct sockaddr_in6 ip6;
#endif
	int specific_ipv4_vhost;
#ifdef IPV6
	int specific_ipv6_vhost;
#endif
};

struct admin_info
{
	char *name;
	char *description;
	char *email;
};

/* All variables are GLOBAL */
extern int specific_ipv4_vhost;	/* used in s_bsd.c */
extern int specific_ipv6_vhost;
extern struct config_file_entry ConfigFileEntry;	/* defined in ircd.c */
extern struct config_channel_entry ConfigChannel;	/* defined in channel.c */
extern struct config_server_hide ConfigServerHide;	/* defined in s_conf.c */
extern struct server_info ServerInfo;	/* defined in ircd.c */
extern struct admin_info AdminInfo;	/* defined in ircd.c */
/* End GLOBAL section */

#ifdef ENABLE_SERVICES
dlink_list service_list;
#endif

typedef enum temp_list
{
	TEMP_MIN,
	TEMP_HOUR,
	TEMP_DAY,
	TEMP_WEEK,
	LAST_TEMP_TYPE
} temp_list;

dlink_list temp_klines[LAST_TEMP_TYPE];
dlink_list temp_dlines[LAST_TEMP_TYPE];

extern void init_s_conf(void);

extern struct ConfItem *make_conf(void);
extern void free_conf(struct ConfItem *);

extern void read_conf_files(int cold);

extern int attach_conf(struct Client *, struct ConfItem *);
extern int check_client(struct Client *client_p, struct Client *source_p, const char *);

extern int detach_conf(struct Client *);

extern struct ConfItem *find_tkline(const char *, const char *, struct sockaddr *);
extern char *show_iline_prefix(struct Client *, struct ConfItem *, char *);
extern void get_printable_conf(struct ConfItem *,
			       char **, char **, char **, char **, int *, char **);
extern void get_printable_kline(struct Client *, struct ConfItem *,
				char **, char **, char **, char **);

extern void yyerror(const char *);
extern int conf_yy_fatal_error(const char *);
extern int conf_fgets(char *, int, FILE *);

typedef enum
{
	CONF_TYPE,
	KLINE_TYPE,
	DLINE_TYPE,
	RESV_TYPE
}
KlineType;

extern void write_confitem(KlineType, struct Client *, char *, char *,
			   const char *, const char *, const char *, int);
extern void add_temp_kline(struct ConfItem *);
extern void add_temp_dline(struct ConfItem *);
extern void report_temp_klines(struct Client *);
extern void show_temp_klines(struct Client *, dlink_list *);

extern const char *get_conf_name(KlineType);
extern int rehash(int);
extern void rehash_bans(int);

extern int conf_add_server(struct ConfItem *, int);
extern void conf_add_class_to_conf(struct ConfItem *, const char *name);
extern void conf_add_me(struct ConfItem *);
extern void conf_add_class(struct ConfItem *, int);
extern void conf_add_d_conf(struct ConfItem *);
extern void flush_expired_ips(void *);


/* XXX consider moving these into kdparse.h */
extern void parse_k_file(FILE * fb);
extern void parse_d_file(FILE * fb);
extern void parse_x_file(FILE * fb);
extern void parse_resv_file(FILE *);
extern char *getfield(char *newline);

extern char *get_oper_name(struct Client *client_p);
char *get_class_name(struct ConfItem *aconf);

extern int yylex(void);

extern unsigned long cidr_to_bitmask[];

extern char conffilebuf[IRCD_BUFSIZE + 1];
extern int lineno;

#define NOT_AUTHORISED  (-1)
#define SOCKET_ERROR    (-2)
#define I_LINE_FULL     (-3)
#define BANNED_CLIENT   (-4)
#define TOO_MANY_LOCAL	(-6)
#define TOO_MANY_GLOBAL (-7)
#define TOO_MANY_IDENT	(-8)

#endif /* INCLUDED_s_conf_h */
