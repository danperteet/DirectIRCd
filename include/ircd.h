/*
 *  ircd-ratbox: A slightly useful ircd.
 *  ircd.h: A header for the ircd startup routines.
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
 *  $Id: ircd.h 21852 2006-02-07 19:29:02Z leeh $
 */

#ifndef INCLUDED_ircd_h
#define INCLUDED_ircd_h

#include "config.h"
#include "tools.h"
#include "memory.h"

struct Client;
struct dlink_list;

struct SetOptions
{
	int maxclients;		/* max clients allowed */
	int autoconn;		/* autoconn enabled for all servers? */

	int idletime;

	int floodcount;		/* Number of messages in 1 second */
	int ident_timeout;	/* timeout for identd lookups */

	int spam_num;
	int spam_time;

	char operstring[REALLEN];
	char adminstring[REALLEN];
};

struct Counter
{
	int oper;		/* Opers */
	int total;		/* total clients */
	int invisi;		/* invisible clients */
	int max_loc;		/* MAX local clients */
	int max_tot;		/* MAX global clients */
	unsigned long totalrestartcount;	/* Total client count ever */
};

extern struct SetOptions GlobalSetOptions;	/* defined in ircd.c */

extern const char *creation;
extern const char *generation;
extern const char *platform;
extern const char *infotext[];
extern const char *serno;
extern const char *ircd_version;
extern const char *logFileName;
extern const char *pidFileName;
extern int cold_start;
extern int dorehash;
extern int dorehashbans;
extern int doremotd;
extern int kline_queued;
extern int server_state_foreground;
int conf_parse_failure;

extern struct Client me;
extern dlink_list global_client_list;
extern struct Client *local[];
extern struct Counter Count;
#if 0
extern time_t CurrentTime;
#endif
extern struct timeval SystemTime;
#define CurrentTime SystemTime.tv_sec
extern int default_server_capabs;

extern time_t startup_time;

extern int splitmode;
extern int splitchecking;
extern int split_users;
extern int split_servers;
int eob_count;

extern dlink_list unknown_list;
extern dlink_list lclient_list;
extern dlink_list serv_list;
extern dlink_list global_serv_list;
extern dlink_list oper_list;
extern dlink_list dead_list;

void ircd_shutdown(const char *reason);

extern void get_current_bandwidth(struct Client *source_p, struct Client *target_p);

extern unsigned long get_maxrss(void);
extern void set_time(void);

extern int testing_conf;
extern int maxconnections;

#endif
