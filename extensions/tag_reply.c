/*
 * Solanum: a slightly advanced ircd
 * tag_reply.c: implement the IRCv3 +draft/reply client tag
 *
 * Copyright (c) 2025 Ryan Schmidt <skizzerz@skizzerz.net>
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
#include "client_tags.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "chmode.h"
#include "parse.h"
#include "inline/stringops.h"

static const char tag_reply_desc[] = "Provides support for the +draft/reply client tag.";
static void tag_reply_allow(void *);

mapi_hfn_list_av1 tag_reply_hfnlist[] = {
	{ "message_tag", tag_reply_allow },
	{ NULL, NULL }
};

static int
modinit(void)
{
	add_client_tag("draft/reply");
	return 0;
}

static void
moddeinit(void)
{
	remove_client_tag("draft/reply");
}

static void
tag_reply_allow(void *data_)
{
	hook_data_message_tag *data = data_;

	if (strcmp("+draft/reply", data->key) != 0 || EmptyString(data->value))
		return;

	/* If coming from a client, validate that the reply is a "valid" message id for the message target */
	if (IsClient(data->client))
	{
		if (!IsCapable(data->client, CLICAP_MESSAGE_TAGS))
			return;

		/* not a message? */
		if (strcasecmp(data->message->cmd, "PRIVMSG") != 0 && strcasecmp(data->message->cmd, "NOTICE") != 0 && strcasecmp(data->message->cmd, "TAGMSG") != 0)
			return;

		/* unrecognized message id format? */
		size_t idlen = strlen(data->value);
		if (*data->value != '1' || idlen < 29)
			return;

		/* message lacking a target or sent to multiple targets? */
		if (data->message->n_para < 2 || strchr(data->message->para[1], ',') != NULL)
			return;

		/* check if the target is a channel (possibly a statusmsg) */
		const char *ch_target = NULL;
		if (IsChannelName(data->message->para[1]))
			ch_target = data->message->para[1];
		else if (IsChannelName(data->message->para[1] + 1))
			ch_target = data->message->para[1] + 1;

		if ((ch_target == NULL) ^ (idlen == 29))
			return;

		/* quick validation of msgid portion before channel name */
		for (int i = 1; i < idlen && i < 29; i++)
		{
			if (i < 20 && !isdigit(data->value[i]))
				return;
			if (i >= 20 && !isupper(data->value[i]) && !isdigit(data->value[i]))
				return;
		}

		if (ch_target != NULL)
		{
			int chlen;
			char *chname = rb_base64_decode(data->value + 29, idlen - 29, &chlen);
			bool is_match = irccmp(chname, ch_target);
			rb_free(chname);

			if (!is_match)
				return;
		}
	}

	data->capmask = CLICAP_MESSAGE_TAGS;
	data->approved = MESSAGE_TAG_ALLOW;
}

DECLARE_MODULE_AV2(tag_reply, modinit, moddeinit, NULL, NULL, tag_reply_hfnlist, NULL, NULL, tag_reply_desc);
