/*
 *  ircd-ratbox: A slightly useful ircd.
 *  patchlevel.h: A header defining the patchlevel.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2008 ircd-ratbox development team
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
 *  $Id: patchlevel.h 26746 2010-01-25 16:36:01Z androsyn $
 */

#ifndef PATCHLEVEL
#	define VER_MAJOR "0"
#	define VER_MINOR "2"
#	define VER_PATCH "0"
#	define VERSION_DOTED VER_MAJOR "." VER_MINOR "." VER_PATCH
#	define PROJNAME "DirectIRCd"
#	define PATCHLEVEL   "DirectIRCd-" VERSION_DOTED 
#define PATCHLEVEL_NUM	0202090500

/* patchlevel numbers:
 * <major><minor><point><status><statusnum>
 *
 * Where status is:
 * 0=alpha, 1=beta, 2=rc, 5=release
 */
#endif
