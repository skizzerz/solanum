/*
 * Solanum: a slightly advanced ircd
 * m_capture.c: Makes a designated client captive
 *
 * Copyright (C) 2002-2026 by the past and present ircd coders, and others.
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
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "send.h"

#define LFLAGS_CAPTURED 0x01000000
#define IsCaptured(x) ((x)->localClient->localflags & LFLAGS_CAPTURED)
#define SetCaptured(x) {(x)->localClient->localflags |= LFLAGS_CAPTURED;}
#define ClearCaptured(x) {(x)->localClient->localflags &= ~LFLAGS_CAPTURED;}

static const char capture_desc[] = "CAPTURE system to ignore a client's commands.";
static struct MessageEntry capture_entry = mg_ignore;

static void capture_clear(void *);
static void capture_handler(void *);
static void capture_quit(void *);
static void me_capture(struct MsgBuf *, struct Client *, struct Client *, int, char *[]);
static void mo_capture(struct MsgBuf *, struct Client *, struct Client *, int, char *[]);
static void me_uncapture(struct MsgBuf *, struct Client *, struct Client *, int, char *[]);
static void mo_uncapture(struct MsgBuf *, struct Client *, struct Client *, int, char *[]);

struct Message capture_msgtab = {
	"CAPTURE", 0, 0, 0, 0,
	{ mg_unreg, mg_not_oper, mg_not_oper, mg_ignore, { me_capture, 2 }, { mo_capture, 2 } }
};

struct Message uncapture_msgtab = {
	"UNCAPTURE", 0, 0, 0, 0,
	{ mg_unreg, mg_not_oper, mg_not_oper, mg_ignore, { me_uncapture, 2 }, { mo_uncapture, 2 } }
};

mapi_clist_av1 capture_clist[] = { &capture_msgtab, &uncapture_msgtab, NULL };

mapi_hfn_list_av1 capture_hfn_list[] = {
	{ "client_quit", capture_quit },
	{ "message_handler", capture_handler },
	{ "priv_change", capture_clear },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(m_capture, NULL, NULL, capture_clist, NULL, capture_hfn_list, NULL, NULL, capture_desc);

static void
capture_clear(void *data_)
{
	hook_data_priv_change *data = data_;
	if (MyClient(data->client) && data->new != NULL)
		ClearCaptured(data->client);
}

static void
capture_handler(void *data_)
{
	hook_data *data = data_;
	struct MsgBuf *msgbuf = data->ptr1;
	if (MyClient(data->client)
		&& !IsOper(data->client)
		&& IsCaptured(data->client)
		&& strncmp(msgbuf->cmd, "PONG") != 0
		&& strncmp(msgbuf->cmd, "QUIT") != 0
		&& strncmp(msgbuf->cmd, "OPER") != 0
		&& strncmp(msgbuf->cmd, "CHALLENGE") != 0
	)
	{
		data->ptr2 = &capture_entry;
	}
}

static void
capture_quit(void *data_)
{
	hook_data_client_quit *data = data_;
	if (IsCaptured(data->client))
		data->reason = NULL;
}
