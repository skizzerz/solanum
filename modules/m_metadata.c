/*
 * Solanum: a slightly advanced ircd
 * m_metadata.c: provides support for the METADATA command
 *
 * Copyright (c) 2026 Ryan Schmidt <skizzerz@skizzerz.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hook.h"
#include "modules.h"
#include "msg.h"

static const char metadata_desc[] =
	"Provides the METADATA command to manage custom metadata on users and channels";

static void m_metadata(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_metadata(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void metadata_stats(void *);
static void reload_metadata_conf(void *);
static void send_metadata_conf(void *);
static void send_whois_metadata(void *);

static struct Message metadata_msgtab = {
	"METADATA", 0, 0, 0, 0,
	{mg_unreg, {m_metadata, 2}, mg_ignore, mg_ignore, {me_metadata, 2}, {m_metadata, 2}}
};

mapi_clist_av1 metadata_clist[] = { &metadata_msgtab, NULL };

mapi_hfn_list_av1 metadata_hfnlist[] = {
	{ "conf_read_start", reload_metadata_conf },
	{ "doing_info_conf", send_metadata_conf },
	{ "doing_stats", metadata_stats },
	{ "doing_whois", send_whois_metadata },
	{ "doing_whois_global", send_whois_metadata },
	{ NULL, NULL }
};