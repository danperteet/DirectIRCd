/*
 * Copyright (C) 2004-2005 Lee Hardy <lee -at- leeh.co.uk>
 * Copyright (C) 2004-2005 ircd-ratbox development team
 *
 * $Id: hook.h 18369 2005-01-31 00:16:07Z leeh $
 */
#ifndef INCLUDED_HOOK_H
#define INCLUDED_HOOK_H

typedef struct
{
	char *name;
	dlink_list hooks;
} hook;

typedef void (*hookfn) (void *data);

int h_iosend_id;
int h_iorecv_id;
int h_iorecvctrl_id;

int h_burst_client;
int h_burst_channel;
int h_burst_finished;
int h_server_introduced;

void init_hook(void);
int register_hook(const char *name);
void add_hook(const char *name, hookfn fn);
void remove_hook(const char *name, hookfn fn);
void call_hook(int id, void *arg);

typedef struct
{
	struct Client *client;
	const void *arg1;
	const void *arg2;
} hook_data;

typedef struct
{
	struct Client *client;
	const void *arg1;
	int arg2;
} hook_data_int;

typedef struct
{
	struct Client *client;
	struct Client *target;
} hook_data_client;

typedef struct
{
	struct Client *client;
	struct Channel *chptr;
} hook_data_channel;

typedef struct
{
	struct Client *local_link; /* local client originating this, or NULL */
	struct Client *target; /* dying client */
	struct Client *from; /* causing client (could be &me or target) */
	const char *comment;
} hook_data_client_exit;

#endif
