/*
 *  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
 *  cloak.h: A header for the cloaking system.
 *
 *  Copyright (C) 2005 by the past and present ircd coders, and others.
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
 *  $Id: cloak.h 147 2005-12-26 02:52:10Z jon $
 */

#ifndef INCLUDED_cloak_h
#define INCLUDED_cloak_h

extern void init_cloak(void);
extern char *make_virthost(char *curr, char *new);

#endif /* INCLUDED_cloak_h */
