/*
 *  ircd-ratbox: A slightly useful ircd.
 *  parse.h: A header for the message parser.
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
 *  $Id: parse.h 16071 2004-03-15 17:58:08Z leeh $
 */

#ifndef INCLUDED_parse_h_h
#define INCLUDED_parse_h_h

struct Message;
struct Client;

struct MessageHash
{
	char *cmd;
	struct Message *msg;
	struct MessageHash *next;
};

#define MAX_MSG_HASH  387

extern void parse(struct Client *, char *, char *);
extern void handle_encap(struct Client *, struct Client *, 
		         const char *, int, const char *parv[]);
extern void clear_hash_parse(void);
extern void mod_add_cmd(struct Message *msg);
extern void mod_del_cmd(struct Message *msg);
extern void report_messages(struct Client *);

#endif /* INCLUDED_parse_h_h */
