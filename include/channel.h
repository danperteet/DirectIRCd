/*
 *  ircd-ratbox: A slightly useful ircd.
 *  channel.h: The ircd channel header.
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
 *  $Id: channel.h 23253 2006-10-29 12:28:38Z leeh $
 */

#ifndef INCLUDED_channel_h
#define INCLUDED_channel_h
#include "config.h"		/* config settings */
#include "ircd_defs.h"		/* buffer sizes */

#define MODEBUFLEN      200

/* Maximum mode changes allowed per client, per server is different */
#define MAXMODEPARAMS   4
#define MAXMODEPARAMSSERV 10

struct Client;

/* mode structure for channels */
struct Mode
{
	unsigned int mode;
	int limit;
	char key[KEYLEN];
};

/* channel structure */
struct Channel
{
	dlink_node node;
	struct Mode mode;
	char *topic;
	char *topic_info;
	time_t topic_time;
	time_t last_knock;	/* don't allow knock to flood */

	dlink_list members;	/* channel members */
	dlink_list locmembers;	/* local channel members */

	dlink_list invites;
	dlink_list banlist;
	dlink_list exceptlist;
	dlink_list invexlist;

	time_t first_received_message_time;	/* channel flood control */
	int received_number_of_privmsgs;
	int flood_noticed;

	unsigned long bants;
	time_t channelts;
	char *chname;
};

struct membership
{
	dlink_node channode;
	dlink_node locchannode;
	dlink_node usernode;

	struct Channel *chptr;
	struct Client *client_p;
	unsigned int flags;

	unsigned long bants;
};

#define BANLEN NICKLEN+USERLEN+HOSTLEN+6
struct Ban
{
	char *banstr;
	char *who;
	time_t when;
	dlink_node node;
};

struct ChModeChange
{
	char letter;
	const char *arg;
	const char *id;
	int dir;
	int caps;
	int nocaps;
	int mems;
	struct Client *client;
};

struct ChCapCombo
{
	int count;
	int cap_yes;
	int cap_no;
};

/* can_send results */
#define CAN_SEND_NO	0
#define CAN_SEND_NONOP  1
#define CAN_SEND_OPV	2

/* channel status flags */
#define CHFL_PEON		0x0000	/* normal member of channel */
#define CHFL_CHANOP     	0x0001	/* Channel operator */
#define CHFL_VOICE      	0x0002	/* the power to speak */
#define CHFL_DEOPPED    	0x0004	/* deopped on sjoin, bounce modes */
#define CHFL_BANNED		0x0008  /* cached as banned */
#define ONLY_SERVERS		0x0010
#define ALL_MEMBERS		CHFL_PEON
#define ONLY_CHANOPS		CHFL_CHANOP
#define ONLY_CHANOPSVOICED	(CHFL_CHANOP|CHFL_VOICE)

#define is_chanop(x)	((x) && (x)->flags & CHFL_CHANOP)
#define is_voiced(x)	((x) && (x)->flags & CHFL_VOICE)
#define is_chanop_voiced(x) ((x) && (x)->flags & (CHFL_CHANOP|CHFL_VOICE))
#define is_deop(x)	((x) && (x)->flags & CHFL_DEOPPED)
#define can_send_banned(x) ((x) && (x)->flags & CHFL_BANNED)

/* channel modes ONLY */
#define MODE_PRIVATE    0x0001
#define MODE_SECRET     0x0002
#define MODE_MODERATED  0x0004
#define MODE_TOPICLIMIT 0x0008
#define MODE_INVITEONLY 0x0010
#define MODE_NOPRIVMSGS 0x0020
#define MODE_REGONLY	0x0040
#define CHFL_BAN        0x0100	/* ban channel flag */
#define CHFL_EXCEPTION  0x0200	/* exception to ban channel flag */
#define CHFL_INVEX      0x0400

/* mode flags for direction indication */
#define MODE_QUERY     0
#define MODE_ADD       1
#define MODE_DEL       -1

#define SecretChannel(x)        ((x) && ((x)->mode.mode & MODE_SECRET))
#define HiddenChannel(x)        ((x) && ((x)->mode.mode & MODE_PRIVATE))
#define PubChannel(x)           ((!x) || ((x)->mode.mode &\
                                 (MODE_PRIVATE | MODE_SECRET)) == 0)

/* channel visible */
#define ShowChannel(v,c)        (PubChannel(c) || IsMember((v),(c)))

#define IsMember(who, chan) ((who && who->user && \
                find_channel_membership(chan, who)) ? 1 : 0)

#define IsChannelName(name) ((name) && (*(name) == '#' || *(name) == '&'))

extern dlink_list global_channel_list;
void init_channels(void);

struct Channel *allocate_channel(const char *chname);
void free_channel(struct Channel *chptr);
struct Ban *allocate_ban(const char *, const char *);
void free_ban(struct Ban *bptr);


extern void destroy_channel(struct Channel *);

extern int can_send(struct Channel *chptr, struct Client *who, 
		    struct membership *);
extern int is_banned(struct Channel *chptr, struct Client *who,
		     struct membership *msptr, const char *, const char *);
extern int can_join(struct Client *source_p, struct Channel *chptr, char *key);

extern struct membership *find_channel_membership(struct Channel *, struct Client *);
extern const char *find_channel_status(struct membership *msptr, int combine);
extern void add_user_to_channel(struct Channel *, struct Client *, int flags);
extern void remove_user_from_channel(struct membership *);
extern void remove_user_from_channels(struct Client *);
extern void invalidate_bancache_user(struct Client *);

extern void free_channel_list(dlink_list *);

extern int check_channel_name(const char *name);

extern void channel_member_names(struct Channel *chptr, struct Client *,
				 int show_eon);

extern void del_invite(struct Channel *chptr, struct Client *who);

const char *channel_modes(struct Channel *chptr, struct Client *who);

extern void check_spambot_warning(struct Client *source_p, const char *name);

extern void check_splitmode(void *);

void set_channel_topic(struct Channel *chptr, const char *topic,
		       const char *topic_info, time_t topicts);

extern void init_chcap_usage_counts(void);
extern void set_chcap_usage_counts(struct Client *serv_p);
extern void unset_chcap_usage_counts(struct Client *serv_p);
extern void send_cap_mode_changes(struct Client *client_p, struct Client *source_p,
				  struct Channel *chptr, struct ChModeChange foo[], int);


#endif /* INCLUDED_channel_h */
