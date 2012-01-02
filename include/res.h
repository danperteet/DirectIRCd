/*
 *  ircd-ratbox: A slightly useful ircd.
 *  res.h: A header with the DNS functions.
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
 *  $Id: res.h 22395 2006-05-07 10:23:50Z leeh $
 */

#ifndef _RES_H_INCLUDED
#define _RES_H_INCLUDED 1

#include "config.h"
#include "ircd_defs.h"
#include "adns.h"

struct DNSQuery
{
	void *ptr;
	adns_query query;
	adns_answer answer;
	void (*callback) (void *vptr, adns_answer * reply);
};

void init_resolver(void);
void restart_resolver(void);
void timeout_adns(void *);
void dns_writeable(int fd, void *ptr);
void dns_readable(int fd, void *ptr);
void dns_do_callbacks(void);
void dns_select(void);
int adns_gethost(const char *name, int aftype, struct DNSQuery *req);
int adns_getaddr(struct sockaddr *addr, int aftype, struct DNSQuery *req);
void delete_adns_queries(struct DNSQuery *q);
void report_adns_servers(struct Client *);
#endif
