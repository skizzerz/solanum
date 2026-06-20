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

#include "batch.h"
#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "hook.h"
#include "logger.h"
#include "messages.h"
#include "metadata.h"
#include "modules.h"
#include "monitor.h"
#include "msg.h"
#include "newconf.h"
#include "numeric.h"
#include "ratelimit.h"
#include "response.h"
#include "send.h"
#include "s_assert.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"

/* maximum size of a metadata key */
#define MAX_KEY_BYTES 50

/* If the client has this many or fewer metadata subscriptions, automatic metadata sync is used */
#define SMALL_METADATA_BATCH_SIZE 5

/* bitfields for struct MetadataClient.flags */
#define MC_CMD_SYNC       0x001
#define MC_CMD_LIST       0x002
#define MC_CMD_CLEAR      0x004
#define MC_TARGET_ALL     0x010
#define MC_TARGET_CHANNEL 0x020
#define MC_TARGET_USER    0x040
#define MC_FLAG_OPERSPY   0x100
#define MC_FLAG_OVERRIDE  0x200

#define MetadataEmpty(x) ((x) == NULL || (x)->values.length == 0 || ((x)->flags & METADATA_FLAG_DELETED) == METADATA_FLAG_DELETED)
#define IsMetadataNew(x) ((x) && ((x)->flags & METADATA_FLAG_NEW) == METADATA_FLAG_NEW)
#define MetadataTarget(x) ((x)->type == METADATA_USER ? (x)->target_p->name : (x)->type == METADATA_CHANNEL ? (x)->chptr->chname : (x)->msptr->chptr->chname)
#define MetadataSubject(x) ((x)->type == METADATA_USER ? (x)->target_p->name : (x)->type == METADATA_CHANNEL ? (x)->chptr->chname : (x)->msptr->client_p->name)
#define MetadataTargetId(x) ((x)->type == METADATA_USER ? use_id((x)->target_p) : (x)->type == METADATA_CHANNEL ? (x)->chptr->chname : (x)->msptr->chptr->chname)
#define MetadataSubjectId(x) ((x)->type == METADATA_MEMBER ? use_id((x)->msptr->client_p) : "*")
#define MetadataTs(x) ((x)->type == METADATA_USER ? (x)->target_p->tsinfo : (x)->type == METADATA_CHANNEL ? (x)->chptr->channelts : (x)->msptr->chptr->channelts)
#define IsMCSync(x) ((x) && ((x)->flags & MC_CMD_SYNC) == MC_CMD_SYNC)
#define IsMCList(x) ((x) && ((x)->flags & MC_CMD_LIST) == MC_CMD_LIST)
#define IsMCClear(x) ((x) && ((x)->flags & MC_CMD_CLEAR) == MC_CMD_CLEAR)
#define IsMCTargetAll(x) ((x) && ((x)->flags & MC_TARGET_ALL) == MC_TARGET_ALL)
#define IsMCTargetChannel(x) ((x) && ((x)->flags & MC_TARGET_CHANNEL) == MC_TARGET_CHANNEL)
#define IsMCTargetUser(x) ((x) && ((x)->flags & MC_TARGET_USER) == MC_TARGET_USER)
#define IsMCOperSpy(x) ((x) && ((x)->flags & MC_FLAG_OPERSPY) == MC_FLAG_OPERSPY)
#define IsMCOverride(x) ((x) && ((x)->flags & MC_FLAG_OVERRIDE) == MC_FLAG_OVERRIDE)

#define SYNCLATER_AUTO "Automatic metadata is not supported for this target, please sync manually."
#define SYNCLATER_RATE_LIMIT "This command could not be completed because it has been used recently, and is rate-limited."
#define SYNCLATER_PENDING "A SYNC operation is currently in progress, try again after it has completed."

static const char metadata_desc[] =
	"Provides the METADATA command to manage custom metadata on users and channels";

static const char *default_whois_keys[] = {
	"display-name",
	"pronouns",
	"status",
	NULL
};

static uint64_t CLICAP_METADATA;
static int h_can_metadata;
static int h_set_metadata;
static int h_metadata_permissions;

static int enable_client_command = 0;
static int metadata_max_subs = 100;
static int metadata_max_keys = 100;
static int metadata_max_value_bytes = 300;
static char **allowed_keys = NULL;
static char **denied_keys = NULL;
static char **whois_keys = NULL;
static int old_client_command;
static int old_max_subs;
static int old_max_keys;
static int old_max_value_bytes;
static char metadata_cap_value[BUFSIZE];
static struct ev_entry *iterate_ev = NULL;
static struct ev_entry *purge_ev = NULL;

static rb_dictionary *sub_index;		/* dict of key name to local clients subscribing to the key (value is rb_dlink_list) */
static rb_dictionary *client_index;		/* dict of local clients to the keys they are subscribed to (value is rb_dlink_list) */
static rb_dlink_list metadata_clients;  /* local clients with pending async metadata commands */

/* needs to be in the same ordering as enum metadata_perm */
static const char *metadata_perms[] = {
	"*", /* METADATA_ALLOW_ALL */
	"#", /* METADATA_ALLOW_CHANNEL */
	"@", /* METADATA_ALLOW_OP */
	"@", /* METADATA_ALLOW_OVERRIDE */
	"!", /* METADATA_ALLOW_SELF */
	"o", /* METADATA_ALLOW_AUSPEX */
	"S", /* METADATA_ALLOW_SERVICES */
};

/* needs to be in the same ordering as enum metadata_type */
static const char metadata_chars[] = {
	'U', /* METADATA_USER */
	'C', /* METADATA_CHANNEL */
	'M', /* METADATA_MEMBER */
};

static uint8_t metadata_key_chars[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, /* 0x20-0x2F: 2D '-' 2E '.' 2F '/' */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F: 30-39 are digits */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40-0x4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, /* 0x50-0x5F: 5F '_' */
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60-0x6F: 61-6F are lowercase letters */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 0x70-0x7F: 70-7A are lowercase letters */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x80-0x8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x90-0x9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xA0-0xAF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xB0-0xBF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xC0-0xCF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xD0-0xDF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xE0-0xEF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xF0-0xFF */
};

/* shamelessly lifted from m_cap */
typedef int (*bqcmp)(const void *, const void *);
struct metadata_cmd
{
	const char *cmd;
	int min_para;
	void (*func)(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
};

/* module load/unload */
static int modinit(void);
static void moddeinit(void);

/* rb_dictionary key comparison functions */
static int dict_ptrcmp(const void *p1, const void *p2);

/* commands */
static void m_metadata(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_mda(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_mdd(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_mdi(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_mds(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

/* subcommands */
static void metadata_abort(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_clear(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_get(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_list(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_set(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_sub(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_subs(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_sync(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);
static void metadata_unsub(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[]);

/* command helpers */
static void abort_async_metadata(struct Client *source_p, bool note_noop);
static void metadata_client_instantiate(struct Client *client_p, const char *target, int cmd, bool oper_flag);
static int metadata_cmd_search(const char *command, const struct metadata_cmd *entry);
static bool metadata_filter_subs(struct Client *client_p, void *data_);
static void notify_subs(struct Client *source_p, struct MetadataEntry *entry);
static void set_default_perms(struct Client *source_p, struct MetadataEntry *entry);

/* hooks */
static void check_metadata_snomask(void *);
static void handle_burst_channel(void *);
static void handle_burst_client(void *);
static void handle_cap_change(void *);
static void handle_channel_join(void *);
static void handle_channel_lower_ts(void *);
static void handle_client_exit(void *);
static void handle_introduce_client(void *);
static void handle_new_monitor(void *);
static void metadata_conf_store(void *);
static void metadata_conf_update(void *);
static void metadata_rehash(void *);
static void metadata_stats(void *);
static void send_metadata_conf(void *);
static void send_metadata_welcome(void *);
static void send_whois_metadata(void *);

/* client capability */
static bool cap_metadata_visible(struct Client *client_p);
static const char *cap_metadata_data(struct Client *client_p);

/* ircd.conf */
static void conf_set_allow_keys(void *);
static void conf_set_deny_keys(void *);
static void conf_set_whois_keys(void *);

/* scheduled events */
static void metadata_iterate_clients(void *);
static void metadata_purge_deleted(void *);

/* scheduled event helpers */
static void metadata_iterate_client(struct Client *client_p);
static rb_dlink_node *metadata_iterate_next(struct Client *client_p);
static rb_dlink_node *metadata_iterate_resume(struct Client *client_p);
static rb_dlink_node *metadata_iterate_resume_all(struct Client *client_p);
static rb_dlink_node *metadata_iterate_resume_channel(struct Client *client_p);
static rb_dlink_node *metadata_iterate_resume_user(struct Client *client_p);

/* memory cleanup */
static void cleanup_index(rb_dictionary_element *elem, void *free_key);
static void free_conf_list(char ***list);
static void metadata_client_release(struct Client *client_p);
static void remove_all_subs(struct Client *client_p);

/* general helper functions */
static bool metadata_key_valid(const char *key);
static const char *sanitize_middle_param(const char *value);
static enum metadata_perm metadata_read_perm(struct Client *client_p, const struct MetadataEntry *entry, bool operspy);
static enum metadata_perm metadata_write_perm(struct Client *client_p, const struct MetadataEntry *entry, int dir, bool override);
static bool str_in_list(rb_dlink_list *list, const char *str);
static unsigned long channel_metadata_length(const struct Channel *chptr, bool count_all);
static unsigned long user_metadata_length(const struct Client *client_p, bool count_all);
static const char *expand_key(const struct MetadataEntry *entry);

static struct metadata_cmd metadata_cmdlist[] = {
	/* This list *MUST* be in alphabetical order */
	{ "ABORT", 3, metadata_abort },
	{ "CLEAR", 3, metadata_clear },
	{ "GET",   4, metadata_get   },
	{ "LIST",  3, metadata_list  },
	{ "SET",   4, metadata_set   },
	{ "SUB",   4, metadata_sub   },
	{ "SUBS",  3, metadata_subs  },
	{ "SYNC",  3, metadata_sync  },
	{ "UNSUB", 4, metadata_unsub },
};

static struct ClientCapability capdata_metadata = {
	.visible = cap_metadata_visible,
	.data = cap_metadata_data,
};

static struct Message metadata_msgtab = {
	"METADATA", 0, 0, 0, 0,
	{mg_unreg, {m_metadata, 3}, mg_ignore, mg_ignore, mg_ignore, {m_metadata, 3}}
};

static struct Message mda_msgtab = {
	"MDA", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_mda, 8}, mg_ignore}
};

static struct Message mdd_msgtab = {
	"MDD", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_mdd, 7}, mg_ignore}
};

static struct Message mdi_msgtab = {
	"MDI", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_mdi, 11}, mg_ignore}
};

static struct Message mds_msgtab = {
	"MDS", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_mds, 8}, mg_ignore}
};

mapi_clist_av1 metadata_clist[] = {
	&metadata_msgtab,
	&mda_msgtab,
	&mdd_msgtab,
	&mdi_msgtab,
	&mds_msgtab,
	NULL
};

mapi_cap_list_av2 metadata_caplist[] = {
	{ MAPI_CAP_CLIENT, "draft/metadata-3", &capdata_metadata, &CLICAP_METADATA },
	{ 0, NULL, NULL, NULL }
};

mapi_hlist_av1 metadata_hlist[] = {
	{ "can_metadata", &h_can_metadata },
	{ "set_metadata", &h_set_metadata },
	{ "metadata_permissions", &h_metadata_permissions },
	{ NULL, NULL }
};

mapi_hfn_list_av1 metadata_hfnlist[] = {
	{ "burst_channel", handle_burst_channel },
	{ "burst_client", handle_burst_client },
	{ "cap_change", handle_cap_change },
	{ "channel_join", handle_channel_join },
	{ "channel_lowerts", handle_channel_lower_ts },
	{ "client_exit", handle_client_exit },
	{ "conf_read_end", metadata_conf_update },
	{ "conf_read_start", metadata_conf_store },
	{ "doing_info_conf", send_metadata_conf },
	{ "doing_stats", metadata_stats },
	{ "doing_whois", send_whois_metadata },
	{ "doing_whois_global", send_whois_metadata },
	{ "introduce_client", handle_introduce_client },
	{ "new_monitor", handle_new_monitor },
	{ "rehash", metadata_rehash },
	{ "umode_changed", check_metadata_snomask },
	{ "user_welcome", send_metadata_welcome },
	{ NULL, NULL }
};

static struct ConfEntry conf_metadata_table[] = {
	{ "enable_client_command", CF_YESNO, NULL, 0, &enable_client_command },
	{ "max_subs", CF_INT, NULL, 0, &metadata_max_subs },
	{ "max_keys", CF_INT, NULL, 0, &metadata_max_keys },
	{ "max_value_bytes", CF_INT, NULL, 0, &metadata_max_value_bytes },
	{ "allow_keys", CF_QSTRING | CF_FLIST, conf_set_allow_keys, 0, NULL },
	{ "deny_keys", CF_QSTRING | CF_FLIST, conf_set_deny_keys, 0, NULL },
	{ "whois_keys", CF_QSTRING | CF_FLIST, conf_set_whois_keys, 0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

DECLARE_MODULE_AV2(m_metadata, modinit, moddeinit, metadata_clist, metadata_hlist, metadata_hfnlist, metadata_caplist, NULL, metadata_desc);

static int
modinit(void)
{
	snomask_modes['m'] = find_snomask_slot();
	add_top_conf("metadata", NULL, NULL, conf_metadata_table);
	sub_index = rb_dictionary_create("metadata sub index", rb_strcmp);
	client_index = rb_dictionary_create("metadata client index", dict_ptrcmp);
	iterate_ev = rb_event_add("metadata_iterate_clients", metadata_iterate_clients, NULL, 3);
	purge_ev = rb_event_addish("metadata_purge_deleted", metadata_purge_deleted, NULL, 300);
	return 0;
}

static void
moddeinit(void)
{
	rb_dlink_node *ptr, *nptr;

	snomask_modes['m'] = 0;
	remove_top_conf("metadata");
	rb_event_delete(iterate_ev);
	rb_event_delete(purge_ev);
	rb_dictionary_destroy(client_index, cleanup_index, (void *)0);
	rb_dictionary_destroy(sub_index, cleanup_index, (void *)1);
	free_conf_list(&allowed_keys);
	free_conf_list(&denied_keys);
	free_conf_list(&whois_keys);

	RB_DLINK_FOREACH_SAFE(ptr, nptr, metadata_clients.head)
	{
		/* This call removes ptr from the metadata_clients list */
		abort_async_metadata(ptr->data, false);
	}
}

static int
dict_ptrcmp(const void *p1, const void *p2)
{
	intptr_t res = p1 - p2;
	return (res > 0) - (res < 0);
}

static void
cleanup_index(rb_dictionary_element *elem, void *free_key)
{
	rb_dlink_node *ptr, *nptr;
	rb_dlink_list *list = elem->data;

	RB_DLINK_FOREACH_SAFE(ptr, nptr, list->head)
	{
		rb_dlinkDestroy(ptr, list);
	}

	if (free_key)
		rb_free((char *)elem->key);
	rb_free(list);
}

static void
free_conf_list(char ***list)
{
	if (*list != NULL)
	{
		for (int i = 0; (*list)[i] != NULL; i++)
			rb_free((*list)[i]);
		rb_free(*list);
		*list = NULL;
	}
}

static void
metadata_client_release(struct Client *client_p)
{
	if (!MyClient(client_p) || client_p->localClient->metadata_data == NULL)
		return;

	rb_dlinkFindDestroy(client_p, &metadata_clients);
	rb_free(client_p->localClient->metadata_data->target);
	rb_free(client_p->localClient->metadata_data->batch);
	rb_free(client_p->localClient->metadata_data->resume_target);
	rb_free(client_p->localClient->metadata_data->resume_subtarget);
	rb_free(client_p->localClient->metadata_data->resume_key);
	rb_free(client_p->localClient->metadata_data);
	client_p->localClient->metadata_data = NULL;
}

static void
abort_async_metadata(struct Client *source_p, bool note_noop)
{
	if (!MyClient(source_p))
		return;

	struct MetadataClient *data = source_p->localClient->metadata_data;
	if (data == NULL)
	{
		if (note_noop)
			sendto_one(source_p, ":%s NOTE METADATA NO_ASYNC_OP :No in-progress operation to abort", me.name);
		return;
	}

	/* don't try to attach a label to the warning or BATCH end message */
	struct ResponseInfo *info = suspend_response_batch();

	struct MsgTag tag = { "batch", data->batch, CLICAP_BATCH };
	sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
		":%s FAIL METADATA ABORTED %s :%s aborted",
		me.name, data->cmd, data->cmd);
	sendto_one(source_p, ":%s BATCH -%s", me.name, data->batch);
	metadata_client_release(source_p);

	resume_response_batch(info);
}

static bool
str_in_list(rb_dlink_list *list, const char *str)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, list->head)
	{
		if (!strcmp(ptr->data, str))
			return true;
	}

	return false;
}

static const char *
expand_key(const struct MetadataEntry *entry)
{
	static char key[MAX_KEY_BYTES + NICKLEN + 2];

	if (entry->type == METADATA_MEMBER)
	{
		snprintf(key, sizeof(key), "member/%s/%s", entry->msptr->client_p->name, entry->key);
		return key;
	}

	return entry->key;
}

static bool
metadata_key_valid(const char *key)
{
	size_t len = strlen(key);
	if (len == 0 || len > MAX_KEY_BYTES)
		return false;

	for (size_t i = 0; i < len; i++)
	{
		if (!metadata_key_chars[(unsigned char)key[i]])
			return false;
	}

	const char *suffix = key;
	if (!strncmp(key, "member/", 7))
	{
		suffix += 7;
		if (!strncmp(suffix, "private/", 8))
			suffix += 8;
		else if (!strncmp(suffix, "services/", 9))
			suffix += 9;

		/* member keys cannot contain additional slashes outside of private/services namespace */
		if (strchr(suffix, '/') != NULL)
			return false;
	}
	else if (!strncmp(suffix, "private/", 8))
		suffix += 8;
	else if (!strncmp(suffix, "services/", 9))
		suffix += 9;

	if (EmptyString(suffix))
		return false;

	if (denied_keys != NULL)
	{
		for (int i = 0; denied_keys[i] != NULL; i++)
		{
			if (match(denied_keys[i], key))
				return false;
		}
	}

	if (allowed_keys != NULL)
	{
		for (int i = 0; allowed_keys[i] != NULL; i++)
		{
			if (match(allowed_keys[i], key))
				return true;
		}

		/* if any allowed keys are defined, we're in allowlist mode so deny anything that doesn't match */
		return false;
	}

	/* else we're in denylist mode, so getting here means we're good */
	return true;
}

static const char *
sanitize_middle_param(const char *value)
{
	if (EmptyString(value) || *value == ':' || strchr(value, ' ') != NULL)
		return "*";

	return value;
}

static void
set_default_perms(struct Client *source_p, struct MetadataEntry *entry)
{
	hook_data hdata;

	if (!strncmp(entry->key, "private/", 8))
	{
		entry->read = METADATA_ALLOW_AUSPEX;
		entry->write = METADATA_ALLOW_AUSPEX;
		entry->flags |= METADATA_FLAG_EXCLUDE;
	}
	else if (!strncmp(entry->key, "services/", 9))
	{
		entry->read = METADATA_ALLOW_AUSPEX;
		entry->write = METADATA_ALLOW_SERVICES;
		entry->flags |= METADATA_FLAG_EXCLUDE;
	}
	else if (entry->type == METADATA_CHANNEL)
	{
		entry->read = METADATA_ALLOW_CHANNEL;
		entry->write = METADATA_ALLOW_OP;
	}
	else if (entry->type == METADATA_MEMBER)
	{
		entry->read = METADATA_ALLOW_CHANNEL;
		entry->write = METADATA_ALLOW_SELF;
	}
	else if (entry->type == METADATA_USER)
	{
		entry->read = METADATA_ALLOW_ALL;
		entry->write = METADATA_ALLOW_SELF;
	}

	hdata.client = source_p;
	hdata.arg1 = entry;
	hdata.arg2 = NULL;
	call_hook(h_metadata_permissions, &hdata);

	/* don't allow METADATA_FLAG_EXCLUDE if write permissions are lower than METADATA_ALLOW_AUSPEX;
	 * otherwise users could abuse this to exceed the limit */
	if (entry->write < METADATA_ALLOW_AUSPEX)
		entry->flags &= ~METADATA_FLAG_EXCLUDE;
}

static enum metadata_perm
metadata_read_perm(struct Client *client_p, const struct MetadataEntry *entry, bool operspy)
{
	enum metadata_perm result = METADATA_ALLOW_ALL;
	struct membership *msptr;

	if (IsService(client_p))
		result = METADATA_ALLOW_SERVICES;
	else if (entry->read == METADATA_ALLOW_AUSPEX && HasPrivilege(client_p, "auspex:metadata"))
		result = METADATA_ALLOW_AUSPEX; /* auspex:metadata cannot "read down" to lower levels */
	else if (operspy
		|| (entry->type == METADATA_MEMBER && client_p == entry->msptr->client_p)
		|| (entry->type == METADATA_USER && client_p == entry->target_p))
	{
		result = METADATA_ALLOW_SELF;
	}
	else if (entry->type == METADATA_CHANNEL)
	{
		msptr = find_channel_membership(entry->chptr, client_p);
		if (get_channel_access(client_p, entry->chptr, msptr, MODE_QUERY, NULL) >= CHFL_CHANOP)
			result = METADATA_ALLOW_OP;
		else if (msptr != NULL)
			result = METADATA_ALLOW_CHANNEL;
	}
	else if (entry->type == METADATA_MEMBER)
	{
		msptr = find_channel_membership(entry->msptr->chptr, client_p);
		if (get_channel_access(client_p, entry->msptr->chptr, msptr, MODE_QUERY, NULL) >= CHFL_CHANOP)
			result = METADATA_ALLOW_OP;
		else if (msptr != NULL)
			result = METADATA_ALLOW_CHANNEL;
	}
	else if (entry->type == METADATA_USER && has_common_channel(client_p, entry->target_p))
		result = METADATA_ALLOW_CHANNEL;

	hook_data_int hdata = { client_p, entry, MODE_QUERY, result };
	call_hook(h_can_metadata, &hdata);
	return hdata.result;
}

static enum metadata_perm
metadata_write_perm(struct Client *client_p, const struct MetadataEntry *entry, int dir, bool override)
{
	enum metadata_perm result = METADATA_ALLOW_ALL;
	struct membership *msptr;

	if (IsService(client_p))
		result = METADATA_ALLOW_SERVICES;
	else if (entry->write == METADATA_ALLOW_AUSPEX && HasPrivilege(client_p, "auspex:metadata"))
		result = METADATA_ALLOW_AUSPEX; /* auspex:metadata cannot "write down" to lower levels */
	else if (entry->type == METADATA_CHANNEL)
	{
		if (override)
			result = METADATA_ALLOW_OVERRIDE;
		else
		{
			msptr = find_channel_membership(entry->chptr, client_p);
			if (get_channel_access(client_p, entry->chptr, msptr, MODE_QUERY, NULL) >= CHFL_CHANOP)
				result = METADATA_ALLOW_OP;
		}
	}
	else if ((entry->type == METADATA_MEMBER && client_p == entry->msptr->client_p)
		|| (entry->type == METADATA_USER && client_p == entry->target_p))
	{
		result = METADATA_ALLOW_SELF;
	}

	hook_data_int hdata = { client_p, entry, dir, result };
	call_hook(h_can_metadata, &hdata);
	return hdata.result;
}

/* In addition to having the ability to read a key, a subscriber should only be notified for changes to:
 * - themselves,
 * - channels they are joined to,
 * - other clients channels they are joined to, and
 * - users they are currently monitoring.
 *
 * As such, we skip notifications for otherwise readable keys if they don't fit in one of the above categories.
 */
static bool
metadata_filter_subs(struct Client *client_p, void *data_)
{
	struct MetadataEntry *entry = data_;
	rb_dlink_list *subs = rb_dictionary_retrieve(client_index, client_p);

	if (subs == NULL || !str_in_list(subs, entry->key))
		return false;

	if (entry->type == METADATA_CHANNEL)
	{
		if (find_channel_membership(entry->chptr, client_p) == NULL)
			return false;
	}
	else if (entry->type == METADATA_USER)
	{
		if (client_p != entry->target_p
			&& !has_common_channel(client_p, entry->target_p)
			&& !is_monitoring(client_p, entry->target_p->name))
		{
			return false;
		}
	}
	else if (entry->type == METADATA_MEMBER)
	{
		if (client_p != entry->msptr->client_p
			&& find_channel_membership(entry->msptr->chptr, client_p) == NULL)
		{
			return false;
		}
	}

	if (metadata_read_perm(client_p, entry, false) < entry->read)
		return false;

	return true;
}

static void
notify_subs(struct Client *source_p, struct MetadataEntry *entry)
{
	rb_dlink_list *subs = rb_dictionary_retrieve(sub_index, entry->key);
	const char *value = MetadataEmpty(entry) ? NULL : entry->values.head->data;

	if (entry->type == METADATA_MEMBER)
		sendto_realops_snomask(snomask_modes['m'], L_ALL, "METADATA:MEMBER: %s/%s %s [%s]",
			entry->msptr->chptr->chname, entry->msptr->client_p->name, entry->key, value);
	else
		sendto_realops_snomask(snomask_modes['m'], L_ALL, "METADATA:%s: %s %s [%s]",
			entry->type == METADATA_USER ? "USER" : "CHANNEL",
			entry->type == METADATA_USER ? entry->target_p->name : entry->chptr->chname, entry->key, value);

	if (subs != NULL)
	{
		if (value == NULL)
			sendto_list_local_butone(source_p, source_p, subs, CLICAP_METADATA | CLICAP_BATCH, NOCAPS,
				metadata_filter_subs, entry, form_str(RPL_KEYNOTSET),
				me.name, "*", MetadataTarget(entry), expand_key(entry));
		else
			sendto_list_local_butone(source_p, source_p, subs, CLICAP_METADATA | CLICAP_BATCH, NOCAPS,
				metadata_filter_subs, entry, form_str(RPL_KEYVALUE),
				me.name, "*", MetadataTarget(entry), expand_key(entry), metadata_perms[entry->read], value);
	}
}

static unsigned long
channel_metadata_length(const struct Channel *chptr, bool count_all)
{
	rb_dlink_node *p1;
	unsigned long length = 0;
	if (count_all)
		length = rb_dlink_list_length(&chptr->metadata);
	else
	{
		RB_DLINK_FOREACH(p1, chptr->metadata.head)
		{
			struct MetadataEntry *entry = p1->data;
			if (entry->flags & (METADATA_FLAG_DELETED | METADATA_FLAG_EXCLUDE))
				continue;
			length++;
		}
	}

	return length;
}

static unsigned long
user_metadata_length(const struct Client *client_p, bool count_all)
{
	rb_dlink_node *p1, *p2;
	unsigned long length = 0;
	if (count_all)
		length = rb_dlink_list_length(&client_p->metadata);
	else
	{
		RB_DLINK_FOREACH(p1, client_p->metadata.head)
		{
			struct MetadataEntry *entry = p1->data;
			if (entry->flags & (METADATA_FLAG_DELETED | METADATA_FLAG_EXCLUDE))
				continue;
			length++;
		}
	}

	RB_DLINK_FOREACH(p1, client_p->user->channel.head)
	{
		const struct membership *msptr = p1->data;
		if (count_all)
			length += rb_dlink_list_length(&msptr->metadata);
		else
		{
			RB_DLINK_FOREACH(p2, msptr->metadata.head)
			{
				struct MetadataEntry *entry = p2->data;
				if (entry->flags & (METADATA_FLAG_DELETED | METADATA_FLAG_EXCLUDE))
					continue;
				length++;
			}
		}
	}

	return length;
}

static bool
cap_metadata_visible(struct Client *client_p)
{
	return enable_client_command;
}

static const char *
cap_metadata_data(struct Client *client_p)
{
	return metadata_cap_value;
}

static void
metadata_conf_store(void *unused)
{
	old_client_command = enable_client_command;
	old_max_subs = metadata_max_subs;
	old_max_keys = metadata_max_keys;
	old_max_value_bytes = metadata_max_value_bytes;
	free_conf_list(&allowed_keys);
	free_conf_list(&denied_keys);
	free_conf_list(&whois_keys);
}

static void
metadata_conf_update(void *unused)
{
	snprintf(metadata_cap_value, sizeof(metadata_cap_value),
		"max-subs=%d,max-keys=%d,max-key-bytes=%d,max-value-bytes=%d,solanum.chat/member",
		metadata_max_subs, metadata_max_keys, MAX_KEY_BYTES, metadata_max_value_bytes);
}

static void
send_metadata_conf(void *data_)
{
	hook_data *data = data_;

	sendto_one(data->client, ":%s %d %s :%-30s %-16s [%s]",
		get_id(&me, data->client), RPL_INFO,
		get_id(data->client, data->client),
		"metadata::enable_client_command",
		enable_client_command ? "YES" : "NO",
		"Whether users can use the METADATA command");

	sendto_one(data->client, ":%s %d %s :%-30s %-16d [%s]",
		get_id(&me, data->client), RPL_INFO,
		get_id(data->client, data->client),
		"metadata::max_subs",
		metadata_max_subs,
		"Max number of metadata keys a user can be subscribed to");

	sendto_one(data->client, ":%s %d %s :%-30s %-16d [%s]",
		get_id(&me, data->client), RPL_INFO,
		get_id(data->client, data->client),
		"metadata::max_keys",
		metadata_max_keys,
		"Max number of metadata keys that can be set on a user/channel");

	sendto_one(data->client, ":%s %d %s :%-30s %-16d [%s]",
		get_id(&me, data->client), RPL_INFO,
		get_id(data->client, data->client),
		"metadata::max_value_bytes",
		metadata_max_value_bytes,
		"Length limit of a metadata value set by a user");
}

static void
metadata_stats(void *data_)
{
	hook_data_int *data = data_;
	rb_dlink_node *ptr;
	rb_dlink_list *list;
	rb_dictionary_iter state;

	if (data->arg2 != 'M')
		return;

	/* for some reason both m and M resolve to the same stats message, but only m is documented
	 * as such, override M always */
	data->result = 1;

	if (!HasPrivilege(data->client, "auspex:metadata"))
	{
		if (IsOper(data->client))
			sendto_one(data->client, form_str(ERR_NOPRIVS), me.name, data->client->name, "auspex:metadata");
		else
			sendto_one_numeric(data->client, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));

		return;
	}

	uint64_t subscribed = rb_dictionary_size(client_index);
	double avg_subscriptions = 0;
	uint64_t max_subscriptions = 0;
	uint64_t unique_keys = rb_dictionary_size(metadata_key_usage);
	uint64_t unique_subscribed_keys = rb_dictionary_size(sub_index);
	uint64_t pending_list_ops = 0;
	uint64_t pending_sync_ops = 0;
	uint64_t pending_clear_ops = 0;
	uint64_t channels = 0;
	uint64_t channel_entries = 0;
	double avg_channel_entries = 0;
	uint64_t max_channel_entries = 0;
	uint64_t users = 0;
	uint64_t user_entries = 0;
	double avg_user_entries = 0;
	uint64_t max_user_entries = 0;

	uint64_t subscriptions = 0;
	RB_DICTIONARY_FOREACH(list, &state, client_index)
	{
		subscriptions += list->length;
		if (list->length > max_subscriptions)
			max_subscriptions = list->length;
	}

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		struct Channel *chptr = ptr->data;
		unsigned long length = channel_metadata_length(chptr, true);
		if (length == 0)
			continue;

		channels++;
		channel_entries += length;
		if (length > max_channel_entries)
			max_channel_entries = length;
	}

	RB_DLINK_FOREACH(ptr, global_client_list.head)
	{
		struct Client *target_p = ptr->data;
		if (!IsPerson(target_p))
			continue;

		unsigned long length = user_metadata_length(target_p, true);
		if (length == 0)
			continue;

		users++;
		user_entries += length;
		if (length > max_user_entries)
			max_user_entries = length;
	}

	RB_DLINK_FOREACH(ptr, metadata_clients.head)
	{
		struct Client *target_p = ptr->data;
		if (IsMCSync(target_p->localClient->metadata_data))
			pending_sync_ops++;
		else if (IsMCList(target_p->localClient->metadata_data))
			pending_list_ops++;
		else if (IsMCClear(target_p->localClient->metadata_data))
			pending_clear_ops++;
	}

	avg_subscriptions = subscribed > 0 ? subscriptions / (double)subscribed : 0;
	avg_channel_entries = channels > 0 ? channel_entries / (double)channels : 0;
	avg_user_entries = users > 0 ? user_entries / (double)users : 0;

	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu %lu Local users (subscribed/total)",
		subscribed, lclient_list.length);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%.2f %lu Subscriptions per client (avg/max)",
		avg_subscriptions, max_subscriptions);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu %lu In-progress LIST/SYNC operations",
		pending_list_ops, pending_sync_ops);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu 0 In-progress CLEAR operations",
		pending_clear_ops);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu %lu Metadata keys (subscribed/defined)",
		unique_subscribed_keys, unique_keys);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu %lu Channels (with metadata/total)",
		channels, global_channel_list.length);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%.2f %lu Entries per channel (avg/max)",
		avg_channel_entries, max_channel_entries);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%lu %d Users (with metadata/total)",
		users, Count.total);
	sendto_one_numeric(data->client, RPL_STATSDEBUG,
		"M :%.2f %lu Entries per client (avg/max)",
		avg_user_entries, max_user_entries);
}

static void
metadata_rehash(void *unused)
{
	rb_dlink_node *ptr, *nptr;

	if (old_client_command && !enable_client_command)
	{
		sendto_local_clients_with_capability(CLICAP_CAP_NOTIFY, ":%s CAP * DEL :draft/metadata-3",
			me.name);

		RB_DLINK_FOREACH(ptr, lclient_list.head)
		{
			ClearClientCap((struct Client *)ptr->data, CLICAP_METADATA);
		}

		/* quick and dirty way to clear all client metadata subscriptions :)
		 * note: the metadata itself is not cleared, just subscriptions
		 */
		rb_dictionary_destroy(client_index, cleanup_index, (void *)0);
		rb_dictionary_destroy(sub_index, cleanup_index, (void *)1);
		sub_index = rb_dictionary_create("metadata sub index", rb_strcmp);
		client_index = rb_dictionary_create("metadata client index", dict_ptrcmp);

		/* also clean up any pending metadata operations */
		RB_DLINK_FOREACH_SAFE(ptr, nptr, metadata_clients.head)
		{
			/* This call removes ptr from the metadata_clients list */
			abort_async_metadata(ptr->data, false);
		}
	}
	else if (old_client_command != enable_client_command
		|| old_max_subs != metadata_max_subs
		|| old_max_keys != metadata_max_keys
		|| old_max_value_bytes != metadata_max_value_bytes)
	{
		sendto_local_clients_with_capability(CLICAP_CAP_NOTIFY, ":%s CAP * NEW :draft/metadata-3=%s",
			me.name, metadata_cap_value);
	}
}

static void
conf_set_allow_keys(void *data)
{
	size_t n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		n++;

	allowed_keys = rb_malloc((n + 1) * sizeof(char *));

	n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		allowed_keys[n++] = rb_strdup(arg->v.string);
	allowed_keys[n] = NULL;
}

static void
conf_set_deny_keys(void *data)
{
	size_t n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		n++;

	denied_keys = rb_malloc((n + 1) * sizeof(char *));

	n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		denied_keys[n++] = rb_strdup(arg->v.string);
	denied_keys[n] = NULL;
}

static void
conf_set_whois_keys(void *data)
{
	size_t n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		n++;

	whois_keys = rb_malloc((n + 1) * sizeof(char *));

	n = 0;
	for (conf_parm_t *arg = data; arg; arg = arg->next)
		whois_keys[n++] = rb_strdup(arg->v.string);
	whois_keys[n] = NULL;
}

static void
check_metadata_snomask(void *data_)
{
	hook_data_umode_changed *data = data_;
	if ((data->client->snomask & snomask_modes['m']) != 0 && !HasPrivilege(data->client, "snomask:metadata"))
	{
		sendto_one_notice(data->client, ":*** You need oper and snomask:metadata for +s +m");
		data->client->snomask &= ~snomask_modes['m'];
	}
}

static void
remove_all_subs(struct Client *client_p)
{
	rb_dlink_node *p, *n;

	if (!MyClient(client_p))
		return;

	rb_dlink_list *list = rb_dictionary_retrieve(client_index, client_p);
	if (list == NULL)
		return;

	RB_DLINK_FOREACH_SAFE(p, n, list->head)
	{
		rb_dictionary_element *elem = rb_dictionary_find(sub_index, p->data);
		if (elem != NULL)
		{
			rb_dlink_list *inner = elem->data;
			char *key = (char *)elem->key;
			rb_dlinkFindDestroy(client_p, inner);

			if (inner->length == 0)
			{
				rb_dictionary_delete(sub_index, key);
				rb_free(key);
			}
		}

		rb_dlinkDestroy(p, list);
	}

	rb_dictionary_delete(client_index, client_p);
}

static void
handle_burst_channel(void *data_)
{
	hook_data_channel *data = data_;
	rb_dlink_node *p1, *p2, *p3;
	struct MetadataEntry *entry;
	bool first;

	RB_DLINK_FOREACH(p1, data->chptr->metadata.head)
	{
		entry = p1->data;
		first = true;
		RB_DLINK_FOREACH(p3, entry->values.head)
		{
			if (first)
			{
				sendto_one(data->client, ":%s ENCAP * MDS C %ld %ld %s * %s :%s",
					me.id, entry->chptr->channelts, entry->tsinfo, entry->chptr->chname,
					entry->key, (const char *)p3->data);
				sendto_one(data->client, ":%s ENCAP * MDI C %ld %ld %s * %s %s %s +%s %s",
					me.id, entry->chptr->channelts, entry->tsinfo, entry->chptr->chname,
					entry->key, metadata_perms[entry->read], metadata_perms[entry->write],
					entry->flags & METADATA_FLAG_EXCLUDE ? "x" : "", entry->setter);
			}
			else
				sendto_one(data->client, ":%s ENCAP * MDA C %ld %ld %s * %s :%s",
					me.id, entry->chptr->channelts, entry->tsinfo, entry->chptr->chname,
					entry->key, (const char *)p3->data);
			first = false;
		}
	}

	RB_DLINK_FOREACH(p1, data->chptr->members.head)
	{
		struct membership *msptr = p1->data;
		RB_DLINK_FOREACH(p2, msptr->metadata.head)
		{
			entry = p2->data;
			first = true;
			RB_DLINK_FOREACH(p3, entry->values.head)
			{
				if (first)
				{
					sendto_one(data->client, ":%s ENCAP * MDS M %ld %ld %s %s %s :%s",
						me.id, entry->chptr->channelts, entry->tsinfo, entry->msptr->chptr->chname, use_id(entry->msptr->client_p),
						entry->key, (const char *)p3->data);
					sendto_one(data->client, ":%s ENCAP * MDI M %ld %ld %s %s %s %s %s +%s %s",
						me.id, entry->chptr->channelts, entry->tsinfo, entry->msptr->chptr->chname, use_id(entry->msptr->client_p),
						entry->key, metadata_perms[entry->read], metadata_perms[entry->write],
						entry->flags & METADATA_FLAG_EXCLUDE ? "x" : "", entry->setter);
				}
				else
					sendto_one(data->client, ":%s ENCAP * MDA M %ld %ld %s %s %s :%s",
						me.id, entry->msptr->chptr->channelts, entry->tsinfo, entry->msptr->chptr->chname,
						use_id(entry->msptr->client_p), entry->key, (const char *)p3->data);
				first = false;
			}
		}
	}
}

static void
handle_burst_client(void *data_)
{
	hook_data_client *data = data_;
	rb_dlink_node *p1, *p2;
	struct MetadataEntry *entry;
	bool first;

	RB_DLINK_FOREACH(p1, data->target->metadata.head)
	{
		entry = p1->data;
		first = true;
		RB_DLINK_FOREACH(p2, entry->values.head)
		{
			if (first)
			{
				sendto_one(data->client, ":%s ENCAP * MDS U %ld %ld %s * %s :%s",
					me.id, entry->chptr->channelts, entry->tsinfo, use_id(entry->target_p),
					entry->key, (const char *)p2->data);
				sendto_one(data->client, ":%s ENCAP * MDI U %ld %ld %s * %s %s %s +%s %s",
					me.id, entry->chptr->channelts, entry->tsinfo, use_id(entry->target_p),
					entry->key, metadata_perms[entry->read], metadata_perms[entry->write],
					entry->flags & METADATA_FLAG_EXCLUDE ? "x" : "", entry->setter);
			}
			else
				sendto_one(data->client, ":%s ENCAP * MDA U %ld %ld %s * %s :%s",
					me.id, entry->target_p->tsinfo, entry->tsinfo, use_id(entry->target_p),
					entry->key, (const char *)p2->data);
			first = false;
		}
	}
}

static void
handle_cap_change(void *data_)
{
	hook_data_cap_change *data = data_;
	if ((data->del & CLICAP_METADATA) != 0)
		remove_all_subs(data->client);
}

static void
handle_channel_join(void *data_)
{
	hook_data_channel_activity *data = data_;
	rb_dlink_list *subs = rb_dictionary_retrieve(client_index, data->client);
	if (!MyClient(data->client) || !IsClientCapable(data->client, CLICAP_METADATA | CLICAP_BATCH) || subs == NULL)
		return;

	/* Send out a batch now if we're only sending out a small number of keys and if we're not close to flooding off */
	if (rb_dlink_list_length(subs) <= SMALL_METADATA_BATCH_SIZE
		&& rb_dlink_list_length(&data->chptr->members) < 20
		&& rb_linebuf_len(&data->client->localClient->buf_sendq) < get_sendq(data->client) / 2
		&& data->client->localClient->metadata_data == NULL)
	{
		metadata_client_instantiate(data->client, data->chptr->chname, MC_CMD_SYNC, false);
		sendto_one(data->client, ":%s BATCH +%s metadata %s",
				me.name, data->client->localClient->metadata_data->batch, data->chptr->chname);
		metadata_iterate_client(data->client);
	}
	else
	{
		/* Otherwise tell clients they need to manually sync */
		sendto_one(data->client, form_str(RPL_METADATASYNCLATER),
			me.name, "*", data->chptr->chname, 0, SYNCLATER_AUTO);
	}

	/* automatic sync for channel join can result in a ton of lines since we need to also sync all channel members.
	 * furthermore, this is often sent by the client in a tight loop on startup, often combined with WHO which has
	 * a lot of lines. As such, always defer syncs for channel joins; ideally, the client does METADATA *ALL SYNC
	 * at the end rather than once sync per channel */
	sendto_one(data->client, form_str(RPL_METADATASYNCLATER),
		me.name, data->client->name, data->chptr->chname, 0, SYNCLATER_AUTO);
}

static void
handle_channel_lower_ts(void *data_)
{
	/* We don't need to propagate these changes as other servers will get the (S)JOIN that lowers the TS
	 * and will run this hook locally as well. Note that member metadata is only writable by self, opers,
	 * or services (never chanops), so there is no need to clear that when channel TS is lowered. */
	hook_data_channel *data = data_;
	rb_dlink_node *ptr, *nptr;

	RB_DLINK_FOREACH_SAFE(ptr, nptr, data->chptr->metadata.head)
	{
		struct MetadataEntry *entry = ptr->data;
		entry->flags |= METADATA_FLAG_DELETED;
		notify_subs(data->client, entry);
		/* this removes the node from the list as well */
		free_metadata(entry);
	}
}

static void
handle_client_exit(void *data_)
{
	hook_data_client_exit *data = data_;
	if (!MyClient(data->target))
		return;

	remove_all_subs(data->target);
	abort_async_metadata(data->target, false);
}

static void
handle_introduce_client(void *data_)
{
	hook_data_client *data = data_;
	struct monitor *monptr = find_monitor(data->target->name, 0);
	char batch_id[BATCH_ID_LEN];
	struct MsgTag tag = { "batch", batch_id, CLICAP_BATCH };
	rb_dlink_node *ptr;

	if (monptr == NULL)
		return;

	/* Send out batches now if the target only has a small handful of metadata keys */
	if (user_metadata_length(data->target, false) <= SMALL_METADATA_BATCH_SIZE)
	{
		generate_batch_id(batch_id, sizeof(batch_id));
		sendto_monitor_with_capability(data->target, monptr, CLICAP_METADATA | CLICAP_BATCH, NOCAPS,
			":%s BATCH +%s metadata %s", me.name, batch_id, data->target->name);
		RB_DLINK_FOREACH(ptr, data->target->metadata.head)
		{
			struct MetadataEntry *entry = ptr->data;
			sendto_list_local_tags_butone(data->target, data->target, &monptr->users,
				CLICAP_METADATA | CLICAP_BATCH, NOCAPS, metadata_filter_subs, entry, 1, &tag,
				form_str(RPL_KEYVALUE), me.name, "*", data->target->name, expand_key(entry),
				metadata_perms[entry->read], (const char *)entry->values.head->data);
		}
		sendto_monitor_with_capability(data->target, monptr, CLICAP_METADATA | CLICAP_BATCH, NOCAPS,
			":%s BATCH -%s metadata", me.name, batch_id);
	}
	else
	{
		/* Otherwise tell clients they need to manually sync */
		sendto_monitor_with_capability(data->target, monptr, CLICAP_METADATA | CLICAP_BATCH, NOCAPS,
			form_str(RPL_METADATASYNCLATER), me.name, "*", data->target->name, 0, SYNCLATER_AUTO);
	}
}

static void
handle_new_monitor(void *data_)
{
	hook_data *data = data_;
	struct Client *target_p = data->arg2;
	rb_dlink_list *subs = rb_dictionary_retrieve(client_index, data->client);
	if (target_p == NULL || !IsClientCapable(data->client, CLICAP_METADATA | CLICAP_BATCH) || subs == NULL)
		return;

	/* Send out a batch now if we're only sending out a small number of keys and if we're not close to flooding off */
	if (rb_dlink_list_length(subs) <= SMALL_METADATA_BATCH_SIZE
		&& rb_linebuf_len(&data->client->localClient->buf_sendq) < get_sendq(data->client) / 2
		&& data->client->localClient->metadata_data == NULL)
	{
		metadata_client_instantiate(data->client, use_id(target_p), MC_CMD_SYNC, false);
		sendto_one(data->client, ":%s BATCH +%s metadata %s",
				me.name, data->client->localClient->metadata_data->batch, target_p->name);
		metadata_iterate_client(data->client);
	}
	else
	{
		/* Otherwise tell clients they need to manually sync */
		sendto_one(data->client, form_str(RPL_METADATASYNCLATER),
			me.name, "*", target_p->name, 0, SYNCLATER_AUTO);
	}
}

static void
send_metadata_welcome(void *data_)
{
	struct Client *client_p = data_;
	rb_dlink_node *p1, *p2;

	if (IsClientCapable(client_p, CLICAP_METADATA | CLICAP_BATCH))
	{
		struct MsgTag tag = { "batch", "761", CLICAP_BATCH };
		sendto_one(client_p, ":%s BATCH +761 metadata %s", me.name, client_p->name);

		/* while a client or remote servers can't use METADATA pre-reg, the new_local_user hook is called before this
		 * and another module may have set metadata on them
		 */
		RB_DLINK_FOREACH(p1, client_p->metadata.head)
		{
			struct MetadataEntry *entry = p1->data;
			enum metadata_perm perm = metadata_read_perm(client_p, entry, false);
			if (perm < entry->read)
				continue;

			RB_DLINK_FOREACH(p2, entry->values.head)
			{
				sendto_one_tags(client_p, NOCAPS, NOCAPS, 1, &tag,
					form_str(RPL_KEYVALUE), me.name, client_p->name, client_p->name,
					entry->key, metadata_perms[entry->read], (char *)p2->data);
			}
		}

		sendto_one(client_p, ":%s BATCH -761", me.name);
	}
}

static void
send_whois_metadata(void *data_)
{
	hook_data_client_approval *data = data_;
	rb_dlink_node *ptr;
	const char **list = whois_keys != NULL ? (const char **)whois_keys : default_whois_keys;

	for (int i = 0; list[i] != NULL; i++)
	{
		const struct MetadataEntry *value = get_user_metadata(data->target, list[i], false);
		if (value == NULL || MetadataEmpty(value))
			continue;

		enum metadata_perm perm = metadata_read_perm(data->client, value, data->approved);
		if (perm >= value->read)
		{
			RB_DLINK_FOREACH(ptr, value->values.head)
			{
				sendto_one_numeric(data->client, RPL_WHOISKEYVALUE, form_str(RPL_WHOISKEYVALUE),
					data->target->name, list[i], metadata_perms[value->read], (char *)ptr->data);
			}
		}
	}
}

static void
metadata_purge_deleted(void *unused)
{
	struct MetadataEntry *entry;
	rb_dlink_node *p1, *p2, *p3, *n;

	RB_DLINK_FOREACH(p1, global_client_list.head)
	{
		struct Client *client_p = p1->data;
		RB_DLINK_FOREACH_SAFE(p2, n, client_p->metadata.head)
		{
			entry = p2->data;
			if (entry->flags & METADATA_FLAG_MARKED)
			{
				/* This removes it from the list we're iterating over as well */
				free_metadata(entry);
			}
			else if (entry->flags & METADATA_FLAG_DELETED || entry->read == METADATA_ALLOW_SERVICES)
			{
				/* A read value of METADATA_ALLOW_SERVICES means we received MDS for a remote key but no follow-up MDI.
				 * Since this key is inaccessible to everyone, purge it too. Getting an MDI later clears the mark. */
				entry->flags |= METADATA_FLAG_MARKED;
			}
		}
	}

	RB_DLINK_FOREACH(p1, global_channel_list.head)
	{
		struct Channel *chptr = p1->data;
		RB_DLINK_FOREACH_SAFE(p2, n, chptr->metadata.head)
		{
			entry = p2->data;
			if (entry->flags & METADATA_FLAG_MARKED)
			{
				/* This removes it from the list we're iterating over as well */
				free_metadata(entry);
			}
			else if (entry->flags & METADATA_FLAG_DELETED)
				entry->flags |= METADATA_FLAG_MARKED;
		}

		RB_DLINK_FOREACH(p2, chptr->members.head)
		{
			struct membership *msptr = p2->data;
			RB_DLINK_FOREACH_SAFE(p3, n, msptr->metadata.head)
			{
				entry = p3->data;
				if (entry->flags & METADATA_FLAG_MARKED)
				{
					/* This removes it from the list we're iterating over as well */
					free_metadata(entry);
				}
				else if (entry->flags & METADATA_FLAG_DELETED)
					entry->flags |= METADATA_FLAG_MARKED;
			}
		}
	}
}

static void
metadata_client_instantiate(struct Client *client_p, const char *target, int cmd, bool oper_flag)
{
	s_assert(MyClient(client_p) && client_p->localClient->metadata_data == NULL);

	struct MetadataClient *data = rb_malloc(sizeof(struct MetadataClient));
	data->flags = cmd;
	if (oper_flag)
		data->flags |= cmd == MC_CMD_CLEAR ? MC_FLAG_OVERRIDE : MC_FLAG_OPERSPY;
	if (!strcmp(target, "*ALL"))
		data->flags |= MC_TARGET_ALL;
	else if (IsChanPrefix(*target))
		data->flags |= MC_TARGET_CHANNEL;
	else
		data->flags |= MC_TARGET_USER;

	switch (cmd)
	{
	case MC_CMD_CLEAR:
		data->cmd = "CLEAR";
		break;
	case MC_CMD_LIST:
		data->cmd = "LIST";
		break;
	case MC_CMD_SYNC:
		data->cmd = "SYNC";
		break;
	}

	data->target = rb_strdup(target);
	data->batch = rb_malloc(BATCH_ID_LEN);
	generate_batch_id(data->batch, BATCH_ID_LEN);
	client_p->localClient->metadata_data = data;
	rb_dlinkAddAlloc(client_p, &metadata_clients);
}

static void
metadata_iterate_clients(void *unused)
{
	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH_SAFE(ptr, nptr, metadata_clients.head)
	{
		/* if we're done iterating data, this will remove the client from the list */
		metadata_iterate_client(ptr->data);
	}
}

static void
metadata_iterate_client(struct Client *client_p)
{
	rb_dlink_node *p1, *p2;
	struct MetadataClient *data = client_p->localClient->metadata_data;
	rb_dlink_list *subs = rb_dictionary_retrieve(client_index, client_p);
	long limit = get_sendq(client_p) / 2;
	struct MsgTag tag = { "batch", data->batch, CLICAP_BATCH };
	int iterations = 0;
	time_t now = rb_current_time();
	char buf[DATALEN+1];
	size_t buf_cur = 0;
	/* maximum that can fit in the remainder of the line after ":<id> ENCAP * MDD <letter> <ts> <ts> <channel> <id> :" */
	size_t buf_max = DATALEN - (IDLEN * 2 + CHANNELLEN + 40);

	/* short-circuit if we're doing SYNC and the client has no subs */
	if (IsMCSync(data) && rb_dlink_list_length(subs) == 0)
	{
		sendto_one(client_p, ":%s BATCH -%s", me.name, data->batch);
		metadata_client_release(client_p);
		return;
	}

	for (rb_dlink_node *start = metadata_iterate_resume(client_p); start != NULL; start = metadata_iterate_next(client_p))
	{
		RB_DLINK_FOREACH(p1, start)
		{
			struct MetadataEntry *entry = p1->data;
			if (MetadataEmpty(entry))
				continue;

			if (IsMCSync(data) && !str_in_list(subs, entry->key))
				continue;

			if (IsMCClear(data))
			{
				if (metadata_write_perm(client_p, entry, MODE_DEL, IsMCOverride(data)) < entry->write)
				{
					if (metadata_read_perm(client_p, entry, IsMCOperSpy(data)) >= entry->read)
						sendto_one_tags(client_p, NOCAPS, NOCAPS, 1, &tag,
							":%1$s WARN METADATA KEY_NO_PERMISSION %2$s %4$s%3$s :You do not have permission to unset %4$s%3$s on %2$s",
							me.name, MetadataSubject(entry), entry->key, entry->type == METADATA_MEMBER ? "member/" : "");

					continue;
				}
			}
			else
			{
				if (metadata_read_perm(client_p, entry, IsMCOperSpy(data)) < entry->read)
					continue;
			}

			/* when doing CLEAR, only do up to 50 keys at a time since we need to send out sub notifications */
			if (rb_linebuf_len(&client_p->localClient->buf_sendq) > limit
				|| (IsMCClear(data) && iterations > 50))
			{
				if (IsMCClear(data) && buf_cur > 0)
					sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS, ":%s ENCAP * MDD %c %ld %ld %s %s :%s",
						me.id, metadata_chars[entry->type], MetadataTs(entry), now,
						MetadataTargetId(entry), MetadataSubjectId(entry), buf);

				/* resume_target, resume_subtarget, and resume_type set by metadata_iterate_resume/metadata_iterate_next */
				rb_free(data->resume_key);
				data->resume_key = rb_strdup(entry->key);
				data->next_target = NULL;
				data->next_subtarget = NULL;
				data->next_node1 = NULL;
				data->next_node2 = NULL;
				return;
			}

			if (IsMCClear(data))
			{
				iterations++;

				if (buf_cur == 0)
				{
					buf_cur = rb_strlcpy(buf, entry->key, sizeof(buf));
				}
				else if (buf_cur + strlen(entry->key) + 1 > buf_max)
				{
					sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS, ":%s ENCAP * MDD %c %ld %ld %s %s :%s",
						me.id, metadata_chars[entry->type], MetadataTs(entry), now,
						MetadataTargetId(entry), MetadataSubjectId(entry), buf);

					buf_cur = rb_strlcpy(buf, entry->key, sizeof(buf));
				}
				else
				{
					buf[buf_cur++] = ' ';
					buf_cur += rb_strlcpy(buf + buf_cur, entry->key, buf_max - buf_cur);
				}

				entry->flags |= METADATA_FLAG_DELETED;
				entry->tsinfo = now;
				notify_subs(client_p, entry);

				sendto_one_tags(client_p, NOCAPS, NOCAPS, 1, &tag,
					form_str(RPL_KEYNOTSET), me.name, client_p->name, MetadataTarget(entry), expand_key(entry));
			}
			else
			{
				RB_DLINK_FOREACH(p2, entry->values.head)
				{
					sendto_one_tags(client_p, NOCAPS, NOCAPS, 1, &tag,
						form_str(RPL_KEYVALUE), me.name, client_p->name, MetadataTarget(entry),
						expand_key(entry), metadata_perms[entry->read], (const char *)p2->data);
				}
			}

			if (p1->next == NULL && IsMCClear(data) && buf_cur > 0)
			{
				sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS, ":%s ENCAP * MDD %c %ld %ld %s %s :%s",
					me.id, metadata_chars[entry->type], MetadataTs(entry), now,
					MetadataTargetId(entry), MetadataSubjectId(entry), buf);

				buf_cur = 0;
			}
		}
	}

	sendto_one(client_p, ":%s BATCH -%s", me.name, data->batch);
	metadata_client_release(client_p);
}

static rb_dlink_node *
metadata_iterate_next(struct Client *client_p)
{
	struct MetadataClient *data = client_p->localClient->metadata_data;
	if (data->next_target == NULL)
		return NULL;

	rb_free(data->resume_target);
	rb_free(data->resume_subtarget);
	rb_free(data->resume_key);
	data->resume_target = rb_strdup(data->next_target);
	data->resume_subtarget = data->next_subtarget != NULL ? rb_strdup(data->next_subtarget) : NULL;
	data->resume_key = NULL;
	return metadata_iterate_resume(client_p);
}

static rb_dlink_node *
metadata_iterate_resume(struct Client *client_p)
{
	struct MetadataClient *data = client_p->localClient->metadata_data;
	if (IsMCTargetAll(data))
		return metadata_iterate_resume_all(client_p);
	if (IsMCTargetChannel(data))
		return metadata_iterate_resume_channel(client_p);
	if (IsMCTargetUser(data))
		return metadata_iterate_resume_user(client_p);
	/* should never happen, but abort the iteration if it does */
	return NULL;
}

static rb_dlink_node *
metadata_iterate_resume_all(struct Client *client_p)
{
	rb_dlink_node *p1, *p2, *p3;
	rb_radixtree_iteration_state state;
	int cmp;
	struct MetadataClient *data = client_p->localClient->metadata_data;
	struct Channel *chptr = NULL;
	struct Client *target_p = NULL;
	struct membership *m1, *m2;

	if (data->resume_target == NULL || IsChanPrefix(*data->resume_target))
	{
		if (data->next_node1 == NULL)
			data->next_node1 = client_p->user->channel.head;

		RB_DLINK_FOREACH(p1, data->next_node1)
		{
			m1 = p1->data;
			cmp = data->resume_target == NULL ? 1 : irccmp(m1->chptr->chname, data->resume_target);
			if (cmp < 0)
				continue;

			if (cmp > 0)
			{
				rb_free(data->resume_target);
				rb_free(data->resume_subtarget);
				rb_free(data->resume_key);
				data->resume_target = rb_strdup(m1->chptr->chname);
				data->resume_subtarget = NULL;
				data->resume_key = NULL;
			}

			RB_DLINK_FOREACH(p3, m1->chptr->metadata.head)
			{
				struct MetadataEntry *entry = p3->data;
				if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
					continue;

				if (p1->next == NULL)
				{
					RB_RADIXTREE_FOREACH(target_p, &state, client_name_tree)
					{
						data->next_target = target_p->name;
						data->next_subtarget = NULL;
						data->next_node1 = NULL;
						data->next_node2 = NULL;
						break;
					}
				}
				else
				{
					data->next_target = ((struct membership *)p1->next->data)->chptr->chname;
					data->next_subtarget = NULL;
					data->next_node1 = p1->next;
					data->next_node2 = NULL;
				}

				rb_free(data->resume_key);
				data->resume_key = NULL;
				return p3;
			}

			/* done iterating keys? */
			rb_free(data->resume_key);
			data->resume_key = NULL;
		}

		/* done iterating channels? */
		if (p1 == NULL)
		{
			rb_free(data->resume_target);
			rb_free(data->resume_subtarget);
			rb_free(data->resume_key);
			data->resume_target = NULL;
			data->resume_subtarget = NULL;
			data->resume_key = NULL;
			data->next_node1 = NULL;
			data->next_node2 = NULL;
		}
	}

	/* not a channel prefix, or we've finished iterating channels (resume_target of NULL starts at beginning) */
	RB_RADIXTREE_FOREACH_FROM(target_p, &state, client_name_tree, data->resume_target)
	{
		/* not a user? */
		if (!IsClient(target_p))
			continue;

		/* verify we share a channel with this user or that they're on our monitor list */
		if (!has_common_channel(client_p, target_p) && !is_monitoring(client_p, target_p->name))
			continue;

		if (data->resume_target == NULL || irccmp(target_p->name, data->resume_target) != 0)
		{
			rb_free(data->resume_target);
			rb_free(data->resume_subtarget);
			rb_free(data->resume_key);
			data->resume_target = rb_strdup(target_p->name);
			data->resume_subtarget = NULL;
			data->resume_key = NULL;
			data->next_node1 = NULL;
			data->next_node2 = NULL;
		}

		if (data->resume_subtarget == NULL)
		{
			RB_DLINK_FOREACH(p3, target_p->metadata.head)
			{
				struct MetadataEntry *entry = p3->data;
				if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
					continue;

				/* we can't easily grab the next node of a radix tree, so provide a sentinel
				 * indicating we're finished with this target instead if we aren't in any channels */
				data->next_target = target_p->name;
				data->next_subtarget = target_p->user->channel.length > 0
					? ((struct membership *)target_p->user->channel.head->data)->chptr->chname
					: "";
				data->next_node1 = IsInvisible(target_p) ? client_p->user->channel.head : target_p->user->channel.head;
				data->next_node2 = target_p->user->channel.head;

				rb_free(data->resume_key);
				data->resume_key = NULL;
				return p3;
			}

			/* done iterating keys? */
			rb_free(data->resume_key);
			data->resume_key = NULL;
		}
		else if (*data->resume_subtarget == '\0')
		{
			/* empty string is a sentinel saying we should skip to next target */
			data->resume_subtarget = NULL;
			data->next_node1 = NULL;
			data->next_node2 = NULL;
			continue;
		}

		/* if only one is NULL, then we're in the middle of ITER_COMM_CHANNELS and one side ran out of channels,
		 * so don't reset to the beginning in that case */
		if (data->next_node1 == NULL && data->next_node2 == NULL)
		{
			data->next_node1 = IsInvisible(target_p) ? client_p->user->channel.head : target_p->user->channel.head;
			data->next_node2 = target_p->user->channel.head;
		}

		ITER_COMM_CHANNELS(p1, p2, data->next_node1, data->next_node2, m1, m2, chptr)
		{
			if (m1 == NULL || m2 == NULL)
				continue;

			cmp = data->resume_subtarget == NULL ? 1 : irccmp(chptr->chname, data->resume_subtarget);
			if (cmp < 0)
				continue;

			if (!ShowChannel(client_p, chptr))
				continue;

			if (cmp > 0)
			{
				rb_free(data->resume_subtarget);
				rb_free(data->resume_key);
				data->resume_subtarget = rb_strdup(chptr->chname);
				data->resume_key = NULL;
			}

			RB_DLINK_FOREACH(p3, m2->metadata.head)
			{
				struct MetadataEntry *entry = p3->data;
				if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
					continue;

				if (p1->next == NULL || p2->next == NULL)
				{
					data->next_target = target_p->name;
					/* sentinel value indicating to skip to the next target (since empty string is never a valid channel name) */
					data->next_subtarget = "";
					data->next_node1 = NULL;
					data->next_node2 = NULL;
				}
				else
				{
					data->next_target = target_p->name;
					data->next_subtarget = ((struct membership *)p1->next->data)->chptr->chname;
					/* advancing both is correct because right now both are pointed at this common channel */
					data->next_node1 = p1->next;
					data->next_node2 = p2->next;
				}

				rb_free(data->resume_key);
				data->resume_key = NULL;
				return p3;
			}

			/* done iterating keys? */
			rb_free(data->resume_key);
			data->resume_key = NULL;
		}
	}

	/* done iterating clients, so we're finished in general */
	return NULL;
}

static rb_dlink_node *
metadata_iterate_resume_channel(struct Client *client_p)
{
	rb_dlink_node *p1, *p2;
	int cmp;
	struct MetadataClient *data = client_p->localClient->metadata_data;
	struct Channel *chptr = find_channel(data->target);

	/* channel no longer exists? */
	if (chptr == NULL)
		return NULL;

	bool in_channel = IsMCOperSpy(data) || IsMember(client_p, chptr);

	if (data->resume_target == NULL)
	{
		RB_DLINK_FOREACH(p1, chptr->metadata.head)
		{
			struct MetadataEntry *entry = p1->data;
			if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
				continue;

			/* if the channel is empty, provide a sentinel value so the next iteration knows to terminate */
			data->next_target = chptr->members.length > 0
				? ((struct membership *)chptr->members.head->data)->client_p->name
				: "";
			data->next_subtarget = NULL;
			data->next_node1 = chptr->members.head;
			data->next_node2 = NULL;

			rb_free(data->resume_key);
			data->resume_key = NULL;
			return p1;
		}
	}
	else if (*data->resume_target == '\0')
	{
		/* sentinel value indicating we've finished */
		return NULL;
	}

	/* done iterating channel metadata, move onto members if this isn't CLEAR */
	if (IsMCClear(data) || (!in_channel && !PubChannel(chptr)))
		return NULL;

	if (data->next_node1 == NULL)
		data->next_node1 = chptr->members.head;

	RB_DLINK_FOREACH(p1, data->next_node1)
	{
		struct membership *msptr = p1->data;
		cmp = data->resume_target == NULL ? 1 : irccmp(msptr->client_p->name, data->resume_target);
		if (cmp < 0)
			continue;

		if (!in_channel && IsInvisible(msptr->client_p))
			continue;

		if (cmp > 0)
		{
			rb_free(data->resume_target);
			rb_free(data->resume_subtarget);
			rb_free(data->resume_key);
			data->resume_target = rb_strdup(msptr->client_p->name);
			data->resume_subtarget = NULL;
			data->resume_key = NULL;
		}

		if (data->resume_subtarget == NULL)
		{
			RB_DLINK_FOREACH(p2, msptr->metadata.head)
			{
				struct MetadataEntry *entry = p2->data;
				if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
					continue;

				/* SYNC iterates into user metadata, LIST does not */
				if (IsMCSync(data))
				{
					data->next_target = msptr->client_p->name;
					data->next_subtarget = msptr->client_p->name;
					data->next_node1 = p1;
					data->next_node2 = NULL;
				}
				else if (p1->next == NULL)
				{
					/* signal end of list */
					data->next_target = "";
					data->next_subtarget = NULL;
					data->next_node1 = NULL;
					data->next_node2 = NULL;
				}
				else
				{
					data->next_target = ((struct membership *)p1->next->data)->client_p->name;
					data->next_subtarget = NULL;
					data->next_node1 = p1->next;
					data->next_node2 = NULL;
				}

				rb_free(data->resume_key);
				data->resume_key = NULL;
				return p2;
			}
		}

		/* done iterating member metadata; we're done with this channel member if this is LIST */
		if (IsMCList(data))
			continue;

		RB_DLINK_FOREACH(p2, msptr->client_p->metadata.head)
		{
			struct MetadataEntry *entry = p2->data;
			if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
				continue;

			if (p1->next == NULL)
			{
				/* signal end of list */
				data->next_target = "";
				data->next_subtarget = NULL;
				data->next_node1 = NULL;
				data->next_node2 = NULL;
			}
			else
			{
				data->next_target = ((struct membership *)p1->next->data)->client_p->name;
				data->next_subtarget = NULL;
				data->next_node1 = p1->next;
				data->next_node2 = NULL;
			}

			rb_free(data->resume_key);
			data->resume_key = NULL;
			return p2;
		}
	}

	/* done iterating members */
	return NULL;
}

static rb_dlink_node *
metadata_iterate_resume_user(struct Client *client_p)
{
	rb_dlink_node *p1, *p2, *p3;
	int cmp;
	struct MetadataClient *data = client_p->localClient->metadata_data;
	struct Client *target_p = find_client(data->target);
	struct membership *m1, *m2;
	struct Channel *chptr;

	/* client no longer exists? */
	if (target_p == NULL)
		return NULL;

	if (data->resume_target == NULL)
	{
		RB_DLINK_FOREACH(p1, target_p->metadata.head)
		{
			struct MetadataEntry *entry = p1->data;
			if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
				continue;

			/* if they aren't in any channels, provide a sentinel value so the next iteration knows to terminate */
			data->next_target = target_p->user->channel.length > 0
				? ((struct membership *)target_p->user->channel.head->data)->chptr->chname
				: "";
			data->next_subtarget = NULL;
			/* if we're doing operspy or they aren't invisible, go over member metadata for all channels;
			 * otherwise, just iterate member metadata for shared channels between the client and target */
			data->next_node1 = IsMCOperSpy(data) || !IsInvisible(target_p) ? target_p->user->channel.head : client_p->user->channel.head;
			data->next_node2 = target_p->user->channel.head;

			rb_free(data->resume_key);
			data->resume_key = NULL;
			return p1;
		}
	}
	else if (*data->resume_target == '\0')
	{
		/* sentinel value indicating we've finished */
		return NULL;
	}

	/* done iterating user metadata, move onto member metadata
	 * if only one is NULL, then we're in the middle of ITER_COMM_CHANNELS and one side ran out of channels,
	 * so don't reset to the beginning in that case */
	if (data->next_node1 == NULL && data->next_node2 == NULL)
	{
		data->next_node1 = IsMCOperSpy(data) || !IsInvisible(target_p) ? target_p->user->channel.head : client_p->user->channel.head;
		data->next_node2 = target_p->user->channel.head;
	}

	ITER_COMM_CHANNELS(p1, p2, data->next_node1, data->next_node2, m1, m2, chptr)
	{
		if (m1 == NULL || m2 == NULL)
			continue;

		cmp = data->resume_target == NULL ? 1 : irccmp(chptr->chname, data->resume_target);
		if (cmp < 0)
			continue;

		if (!IsMCOperSpy(data) && !ShowChannel(client_p, chptr))
			continue;

		if (cmp > 0)
		{
			rb_free(data->resume_target);
			rb_free(data->resume_key);
			data->resume_target = rb_strdup(chptr->chname);
			data->resume_key = NULL;
		}

		RB_DLINK_FOREACH(p3, m2->metadata.head)
		{
			struct MetadataEntry *entry = p3->data;
			if (data->resume_key != NULL && strcmp(entry->key, data->resume_key) < 0)
				continue;

			if (p1->next == NULL || p2->next == NULL)
			{
				/* sentinel value indicating we're finished (since empty string is never a valid channel name) */
				data->next_target = "";
				data->next_node1 = NULL;
				data->next_node2 = NULL;
			}
			else
			{
				data->next_target = ((struct membership *)p1->next->data)->chptr->chname;
				/* advancing both is correct because right now both are pointed at this common channel */
				data->next_node1 = p1->next;
				data->next_node2 = p2->next;
			}

			rb_free(data->resume_key);
			data->resume_key = NULL;
			return p3;
		}

		/* done iterating keys? */
		rb_free(data->resume_key);
		data->resume_key = NULL;
	}

	/* done iterating shared channels */
	return NULL;
}

static void
metadata_abort(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	abort_async_metadata(source_p, true);
}

static void
metadata_clear(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such channel",
				me.name, sanitize_middle_param(target));
			return;
		}

		struct MetadataEntry dummy_entry = {
			.type = METADATA_CHANNEL,
			.key = "*",
			.tsinfo = 0,
			.chptr = chptr,
			.values = { NULL, NULL, 0 },
			.read = METADATA_ALLOW_ALL,
			.write = METADATA_ALLOW_OP,
			.node = NULL,
			.flags = 0,
		};

		enum metadata_perm perm = metadata_write_perm(source_p, &dummy_entry, MODE_DEL, false);
		bool override = perm == METADATA_ALLOW_OVERRIDE;
		if (perm < METADATA_ALLOW_OP && !HasPrivilege(source_p, "auspex:metadata"))
		{
			sendto_one(source_p, ":%1$s FAIL METADATA KEY_NO_PERMISSION %2$s * :You do not have permission to clear keys on %2$s",
				me.name, chptr->chname);
			return;
		}

		abort_async_metadata(source_p, false);
		if (!IsOperGeneral(source_p) && !ratelimit_client(source_p, 1 + channel_metadata_length(chptr, true) / 10))
		{
			sendto_one(source_p, form_str(RPL_LOAD2HI),	me.name, source_p->name, "METADATA");
			return;
		}

		metadata_client_instantiate(source_p, chptr->chname, MC_CMD_CLEAR, override);
		sendto_one(source_p, ":%s BATCH +%s metadata %s",
			me.name, source_p->localClient->metadata_data->batch, chptr->chname);
		metadata_iterate_client(source_p);
	}
	else
	{
		struct Client *target_p = !strcmp(target, "*") ? source_p : find_named_client(target);
		if (target_p == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such nick",
				me.name, sanitize_middle_param(target));
			return;
		}

		if (target_p != source_p && !HasPrivilege(source_p, "auspex:metadata"))
		{
			sendto_one(source_p, ":%1$s FAIL METADATA KEY_NO_PERMISSION %2$s * :You do not have permission to clear keys on %2$s",
				me.name, target_p->name);
			return;
		}

		abort_async_metadata(source_p, false);
		if (!IsOperGeneral(source_p) && !ratelimit_client(source_p, 1 + user_metadata_length(target_p, true) / 10))
		{
			sendto_one(source_p, form_str(RPL_LOAD2HI),	me.name, source_p->name, "METADATA");
			return;
		}

		metadata_client_instantiate(source_p, use_id(target_p), MC_CMD_CLEAR, false);
		sendto_one(source_p, ":%s BATCH +%s metadata %s",
			me.name, source_p->localClient->metadata_data->batch, target_p->name);
		metadata_iterate_client(source_p);
	}
}

static void
metadata_get(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	bool operspy = IsOperSpy(source_p) && *target == '!';
	const char *orig_target = target;
	const char *norm_target;
	struct Channel *chptr = NULL;
	struct Client *target_p = NULL;
	struct MetadataEntry *metadata;
	char batch[BATCH_ID_LEN];
	char buf[BUFSIZE];
	rb_dlink_node *ptr;

	if (operspy)
		target++;
	else if (IsOperSpy(source_p) && !IsChanPrefix(*target) && ConfigFileEntry.operspy_dont_care_user_info)
		operspy = true;

	if (IsChanPrefix(*target))
	{
		chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such channel",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = chptr->chname;
	}
	else
	{
		target_p = !strcmp(target, "*") ? source_p : find_named_client(target);
		if (target_p == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such nick",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = target_p->name;
	}

	if (operspy && (IsChanPrefix(*target) || !ConfigFileEntry.operspy_dont_care_user_info))
	{
		/* in order to accurately report this, we need space for 3 more args for "ENCAP * OPERSPY"
		 * if the user passed too many args for that to fit, reject the operspy attempt
		 * (note: additional offset of 3 because "METADATA <target> GET" was stripped before calling this function) */
		if (parc > MAXPARA - 6)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_PARAMS GET :Too many arguments", me.name);
			return;
		}

		char args[BUFSIZE];
		snprintf(args, sizeof(args), "%s GET", norm_target);
		for (int i = 0; i < parc; i++)
		{
			rb_strlcat(args, " ", sizeof(args));
			rb_strlcat(args, parv[i], sizeof(args));
		}

		report_operspy(source_p, "METADATA", args);
	}

	generate_batch_id(batch, sizeof(batch));
	struct MsgTag tag = { "batch", batch, CLICAP_BATCH };
	sendto_one(source_p, ":%s BATCH +%s metadata %s", me.name, batch, norm_target);

	for (int i = 0; i < parc; i++)
	{
		if (chptr != NULL)
		{
			if (!strncmp(parv[i], "member/", 7))
			{
				rb_strlcpy(buf, parv[i], sizeof(buf));
				char *key = strchr(buf + 7, '/');
				if (key == NULL)
				{
					sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
						":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(parv[i]));
					continue;
				}

				*key++ = '\0';
				target_p = find_named_client(buf + 7);
				if (target_p == NULL)
				{
					sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
						":%s WARN METADATA INVALID_KEY %s :No such nick", me.name, sanitize_middle_param(parv[i]));
					continue;
				}

				/* strip out nickname for validation */
				int j;
				for (j = 0; key[j] != '\0'; j++)
					buf[j + 7] = key[j];
				buf[j + 7] = '\0';

				if (!metadata_key_valid(buf))
				{
					sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
						":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(parv[i]));
					continue;
				}

				struct membership *msptr = find_channel_membership(chptr, target_p);
				if (msptr == NULL)
				{
					/* send RPL_KEYNOTSET to avoid leaking whether the named user is on the channel */
					sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
						form_str(RPL_KEYNOTSET), me.name, source_p->name, target, parv[i]);
					continue;
				}

				metadata = get_member_metadata(msptr, buf + 7, false);
			}
			else
			{
				if (!metadata_key_valid(parv[i]))
				{
					sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
						":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(parv[i]));
					continue;
				}

				metadata = get_channel_metadata(chptr, parv[i], false);
			}
		}
		else
		{
			if (!metadata_key_valid(parv[i]))
			{
				sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
					":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(parv[i]));
				continue;
			}

			metadata = get_user_metadata(target_p, parv[i], false);
		}

		if (MetadataEmpty(metadata) || metadata_read_perm(source_p, metadata, operspy) < metadata->read)
		{
			sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
				form_str(RPL_KEYNOTSET), me.name, source_p->name, norm_target, parv[i]);
			continue;
		}

		RB_DLINK_FOREACH(ptr, metadata->values.head)
		{
			sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
				form_str(RPL_KEYVALUE), me.name, source_p->name, norm_target, parv[i],
				metadata_perms[metadata->read], (char *)ptr->data);
		}
	}

	sendto_one(source_p, ":%s BATCH -%s", me.name, batch);
}

static void
metadata_list(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	bool operspy = IsOperSpy(source_p) && *target == '!';
	const char *orig_target = target;
	const char *norm_target;
	const char *target_id;
	unsigned int tokens;

	if (operspy)
		target++;
	else if (IsOperSpy(source_p) && !IsChanPrefix(*target) && ConfigFileEntry.operspy_dont_care_user_info)
		operspy = true;

	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such channel",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = chptr->chname;
		target_id = chptr->chname;
		tokens = 1 + chptr->members.length / 20;
	}
	else
	{
		struct Client *target_p = !strcmp(target, "*") ? source_p : find_named_client(target);
		if (target_p == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such nick",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = target_p->name;
		target_id = use_id(target_p);
		tokens = 1;
	}

	if (operspy && (IsChanPrefix(*target) || !ConfigFileEntry.operspy_dont_care_user_info))
	{
		char args[BUFSIZE];
		snprintf(args, sizeof(args), "%s LIST", norm_target);
		report_operspy(source_p, "METADATA", args);
	}

	abort_async_metadata(source_p, false);

	if (!IsOperGeneral(source_p) && !ratelimit_client(source_p, tokens))
	{
		sendto_one(source_p, form_str(RPL_LOAD2HI),	me.name, source_p->name, "METADATA");
		return;
	}

	metadata_client_instantiate(source_p, target_id, MC_CMD_LIST, operspy);
	sendto_one(source_p, ":%s BATCH +%s metadata %s",
			me.name, source_p->localClient->metadata_data->batch, norm_target);
	metadata_iterate_client(source_p);
}

static void
metadata_set(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	struct MetadataEntry *entry;
	const char *key = parv[0];
	const char *orig_key = key;
	const char *value = parc < 2 ? "" : parv[1];
	int dir = EmptyString(value) ? MODE_DEL : MODE_ADD;
	const char *norm_target;
	time_t now = rb_current_time();
	char hostmask[USERHOST_REPLYLEN];

	if (!IsOperGeneral(source_p) && !ratelimit_client(source_p, 1))
	{
		sendto_one(source_p, ":%s FAIL METADATA RATE_LIMITED %s %s 2 :" SYNCLATER_RATE_LIMIT,
			me.name, sanitize_middle_param(target), sanitize_middle_param(key));
		return;
	}

	if (!metadata_key_valid(key))
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_KEY %s :Invalid key",
			me.name, sanitize_middle_param(key));
		return;
	}

	if (strlen(value) > metadata_max_value_bytes)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_VALUE %s :Value is too long",
			me.name, key);
		return;
	}

	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such channel",
				me.name, sanitize_middle_param(target));
			return;
		}

		if (!strncmp(key, "member/", 7))
		{
			struct membership *msptr = find_channel_membership(chptr, source_p);
			if (msptr == NULL)
			{
				sendto_one(source_p,
					":%s FAIL METADATA NOT_ON_CHANNEL %s :You must be joined to the channel to set member metadata on it",
					me.name, chptr->chname);
				return;
			}

			key += 7;
			entry = get_member_metadata(msptr, key, false);
			norm_target = chptr->chname;

			if (MetadataEmpty(entry) && user_metadata_length(source_p, false) >= metadata_max_keys)
			{
				sendto_one(source_p, ":%s FAIL METADATA LIMIT_REACHED %s %d :Metadata limit reached",
					me.name, source_p->name, metadata_max_keys);
				return;
			}

			if (entry == NULL)
				entry = get_member_metadata(msptr, key, true);
		}
		else
		{
			entry = get_channel_metadata(chptr, key, false);
			norm_target = chptr->chname;

			if (MetadataEmpty(entry) && channel_metadata_length(chptr, false) >= metadata_max_keys)
			{
				sendto_one(source_p, ":%s FAIL METADATA LIMIT_REACHED %s %d :Metadata limit reached",
					me.name, chptr->chname, metadata_max_keys);
				return;
			}

			if (entry == NULL)
				entry = get_channel_metadata(chptr, key, true);
		}
	}
	else
	{
		struct Client *target_p = !strcmp(target, "*") ? source_p : find_named_client(target);
		if (target_p == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such nick",
				me.name, sanitize_middle_param(target));
			return;
		}

		if (!strncmp(key, "member/", 7))
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_KEY %s :Member metadata may only be set on channels",
				me.name, sanitize_middle_param(orig_key));
			return;
		}

		entry = get_user_metadata(target_p, key, false);
		norm_target = target_p->name;

		if (MetadataEmpty(entry) && user_metadata_length(target_p, false) >= metadata_max_keys)
		{
			sendto_one(source_p, ":%s FAIL METADATA LIMIT_REACHED %s %d :Metadata limit reached",
				me.name, target_p->name, metadata_max_keys);
			return;
		}

		if (entry == NULL)
			entry = get_user_metadata(target_p, key, true);
	}

	if (IsMetadataNew(entry))
		set_default_perms(source_p, entry);

	if (metadata_write_perm(source_p, entry, dir, false) < entry->write)
	{
		sendto_one(source_p, ":%s FAIL METADATA KEY_NO_PERMISSION %s %s :You do not have permission to set %s on %s",
			me.name, norm_target, orig_key, orig_key, norm_target);

		if (IsMetadataNew(entry))
			free_metadata(entry);

		return;
	}

	hook_data_metadata_approval hdata;
	hdata.source = source_p;
	hdata.metadata = entry;
	hdata.value = value;
	hdata.dir = dir;
	hdata.approved = 0;

	call_hook(h_set_metadata, &hdata);
	if (hdata.approved)
	{
		/* hook may have killed the client... */
		if (!IsAnyDead(source_p))
			sendto_one(source_p, ":%s FAIL METADATA INVALID_VALUE %s :Value rejected by server", me.name, key);
		if (IsMetadataNew(entry))
			free_metadata(entry);
		return;
	}

	/* just in case a hook function changed the value on us, update the direction appropriately */
	dir = EmptyString(hdata.value) ? MODE_DEL : MODE_ADD;

	/* trying to delete a nonexistent metadata key? */
	if (IsMetadataNew(entry) && dir == MODE_DEL)
	{
		sendto_one(source_p, form_str(RPL_KEYNOTSET), me.name, source_p->name, norm_target, orig_key);
		free_metadata(entry);
		return;
	}

	/* setting the value to the same as its current value? */
	if (!MetadataEmpty(entry) && entry->values.length == 1 && dir == MODE_ADD && !strcmp(hdata.value, entry->values.head->data))
	{
		sendto_one(source_p, form_str(RPL_KEYVALUE),
			me.name, source_p->name, norm_target, orig_key, metadata_perms[entry->read], hdata.value);
		return;
	}

	/* adjusted value too long? */
	if (dir == MODE_ADD && strlen(hdata.value) > metadata_max_value_bytes)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_VALUE %s :Value is too long after server adjustment",
			me.name, key);
		if (IsMetadataNew(entry))
			free_metadata(entry);
		return;
	}

	entry->tsinfo = now;

	if (dir == MODE_ADD)
	{
		snprintf(hostmask, sizeof(hostmask), "%s!%s@%s",
			source_p->name, source_p->username, source_p->host);
		set_metadata_value(entry, hostmask, hdata.value, false);
		sendto_one(source_p, form_str(RPL_KEYVALUE),
			me.name, source_p->name, norm_target, expand_key(entry), metadata_perms[entry->read], hdata.value);
		sendto_server(source_p, NULL, CAP_ENCAP, NOCAPS,
			":%s ENCAP * MDS %c %ld %ld %s %s %s :%s",
			me.id, metadata_chars[entry->type], MetadataTs(entry), now,
			MetadataTargetId(entry), MetadataSubjectId(entry), key, hdata.value);
		sendto_server(source_p, NULL, CAP_ENCAP, NOCAPS,
			":%s ENCAP * MDI %c %ld %ld %s %s %s %s %s +%s %s",
			me.id, metadata_chars[entry->type], MetadataTs(entry), now,
			MetadataTargetId(entry), MetadataSubjectId(entry), key,
			metadata_perms[entry->read], metadata_perms[entry->write],
			entry->flags & METADATA_FLAG_EXCLUDE ? "x" : "", hostmask);
	}
	else
	{
		entry->flags |= METADATA_FLAG_DELETED;
		sendto_one(source_p, form_str(RPL_KEYNOTSET), me.name, source_p->name, norm_target, expand_key(entry));
		sendto_server(source_p, NULL, CAP_ENCAP, NOCAPS,
			":%s ENCAP * MDD %c %ld %ld %s %s :%s",
			me.id, metadata_chars[entry->type], MetadataTs(entry), now,
			MetadataTargetId(entry), MetadataSubjectId(entry), key);
	}

	notify_subs(source_p, entry);
}

static void
metadata_sub(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	int added = 0;
	int dupes = 0;
	rb_dlink_list *client_subs = rb_dictionary_retrieve(client_index, source_p);
	rb_dlink_node *ptr;

	if (strcmp(target, "*") != 0 && irccmp(target, source_p->name) != 0)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :You may only target yourself",
			me.name, sanitize_middle_param(target));
		return;
	}

	if (client_subs == NULL)
	{
		client_subs = rb_malloc(sizeof(rb_dlink_list));
		rb_dictionary_add(client_index, source_p, client_subs);
	}

	begin_local_response_batch();
	send_multiline_init(source_p, " ", form_str(RPL_METADATASUBOK), me.name, source_p->name);
	for (int i = 0; i < parc; i++)
	{
		const char *key = parv[i];
		if (!metadata_key_valid(key))
		{
			sendto_one(source_p, ":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(key));
			continue;
		}

		rb_dictionary_element *sub_elem = rb_dictionary_find(sub_index, key);
		if (sub_elem != NULL)
		{
			bool dupe = false;
			/* check the smallest list for if this is a duplicate subscription */
			if (rb_dlink_list_length((rb_dlink_list *)sub_elem->data) < rb_dlink_list_length(client_subs))
				dupe = rb_dlinkFind(source_p, sub_elem->data) != NULL;
			else
				dupe = rb_dlinkFind((char *)sub_elem->key, client_subs) != NULL;

			if (dupe)
			{
				dupes++;
				send_multiline_item(source_p, "%s", key);
				continue;
			}
		}

		if (client_subs->length >= metadata_max_subs)
		{
			sendto_one(source_p, ":%s FAIL METADATA LIMIT_REACHED %s %d :Too many subscriptions",
				me.name, key, metadata_max_subs);
			break;
		}

		added++;
		if (sub_elem == NULL)
			sub_elem = rb_dictionary_add(sub_index, rb_strdup(key), rb_malloc(sizeof(rb_dlink_list)));

		if (!rb_dlinkFind(source_p, sub_elem->data))
			rb_dlinkAddAlloc(source_p, sub_elem->data);

		RB_DLINK_FOREACH(ptr, client_subs->head)
		{
			if (strcmp(key, ptr->data) < 0)
				break;
		}

		if (ptr == NULL)
			rb_dlinkAddTailAlloc((char *)sub_elem->key, client_subs);
		else
			rb_dlinkAddBefore(ptr, (char *)sub_elem->key, rb_make_rb_dlink_node(), client_subs);

		send_multiline_item(source_p, "%s", key);
	}

	if (added || dupes)
	{
		send_multiline_fini(source_p, NULL);
		if (added)
			sendto_one(source_p, form_str(RPL_METADATASYNCLATER), me.name, source_p->name, "*ALL", 0, SYNCLATER_AUTO);
	}
	else
		send_multiline_reset();
}

static void
metadata_subs(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	rb_dlink_list *list = rb_dictionary_retrieve(client_index, source_p);
	rb_dlink_node *ptr;
	char buf[DATALEN];
	char batch[BATCH_ID_LEN];
	int items = 0;
	size_t accum = 0;
	struct MsgTag tag = { "batch", batch, CLICAP_BATCH };

	if (strcmp(target, "*") != 0 && irccmp(target, source_p->name) != 0)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :You may only target yourself",
			me.name, sanitize_middle_param(target));
		return;
	}

	generate_batch_id(batch, sizeof(batch));
	sendto_one(source_p, ":%s BATCH +%s metadata-subs", me.name, batch);
	if (list != NULL)
	{
		snprintf(buf, sizeof(buf), form_str(RPL_METADATASUBS), me.name, source_p->name, "");
		size_t max = DATALEN - strlen(buf);

		RB_DLINK_FOREACH(ptr, list->head)
		{
			const char *key = ptr->data;
			size_t len = strlen(key);
			items++;

			if (items == 13 || accum + len + 1 > max)
			{
				sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
					form_str(RPL_METADATASUBS), me.name, source_p->name, buf);
				items = 0;
				accum = 0;
				*buf = '\0';
			}

			if (accum != 0)
				buf[accum++] = ' ';

			rb_strlcpy(buf + accum, key, max - accum);
			accum += len;
		}
	}

	if (accum > 0)
		sendto_one_tags(source_p, NOCAPS, NOCAPS, 1, &tag,
			form_str(RPL_METADATASUBS), me.name, source_p->name, buf);

	sendto_one(source_p, ":%s BATCH -%s", me.name, batch);
}

static void
metadata_sync(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	const char *orig_target = target;
	const char *norm_target;
	const char *target_id;
	rb_dlink_list *subs = rb_dictionary_retrieve(client_index, source_p);
	unsigned int tokens = 1;

	if (!strcmp(target, "*ALL"))
	{
		norm_target = "*ALL";
		target_id = "*ALL";
		/* rate limit this severely due to the potential for a lot of traffic */
		tokens = ConfigFileEntry.max_ratelimit_tokens * 0.7;
	}
	else if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such channel",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = chptr->chname;
		target_id = chptr->chname;
	}
	else
	{
		struct Client *target_p = !strcmp(target, "*") ? source_p : find_named_client(target);
		if (target_p == NULL)
		{
			sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :No such nick",
				me.name, sanitize_middle_param(orig_target));
			return;
		}

		norm_target = target_p->name;
		target_id = use_id(target_p);
	}

	if (subs == NULL || rb_dlink_list_length(subs) == 0)
	{
		sendto_one(source_p, ":%s BATCH +761 metadata %s", me.name, norm_target);
		sendto_one(source_p, ":%s BATCH -761", me.name);
		return;
	}

	/* A client may send multiple METADATA SYNC commands in short succession,
	 * e.g. in response to getting RPL_METADATASYNCLATER for multiple channel joins;
	 * don't abort previous SYNCs in this instance and just tell them to retry in a few seconds
	 * (3 chosen because that's roughly how often the event loop fills up the SendQ for pending SYNCs)
	 */
	if (IsMCSync(source_p->localClient->metadata_data))
	{
		/* if it's the same target, just abort the second sync attempt */
		if (!irccmp(norm_target, source_p->localClient->metadata_data->target))
			sendto_one(source_p, ":%s FAIL METADATA IN_PROGRESS %s :A SYNC operation for %s is already in progress",
				me.name, norm_target, norm_target);
		else
			sendto_one(source_p, form_str(RPL_METADATASYNCLATER),
				me.name, source_p->name, norm_target, 3, SYNCLATER_PENDING);
		return;
	}

	abort_async_metadata(source_p, false);
	if (!IsOperGeneral(source_p) && !ratelimit_client(source_p, tokens))
	{
		sendto_one(source_p, form_str(RPL_METADATASYNCLATER),
			me.name, source_p->name, norm_target, tokens, SYNCLATER_RATE_LIMIT);
		return;
	}

	metadata_client_instantiate(source_p, target_id, MC_CMD_SYNC, false);
	sendto_one(source_p, ":%s BATCH +%s metadata %s",
			me.name, source_p->localClient->metadata_data->batch, norm_target);
	metadata_iterate_client(source_p);
}

static void
metadata_unsub(struct MsgBuf *msgbuf, struct Client *source_p, const char *target, int parc, const char *parv[])
{
	int count = 0;
	rb_dlink_list *client_subs = rb_dictionary_retrieve(client_index, source_p);

	if (strcmp(target, "*") != 0 && irccmp(target, source_p->name) != 0)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_TARGET %s :You may only target yourself",
			me.name, sanitize_middle_param(target));
		return;
	}

	begin_local_response_batch();
	send_multiline_init(source_p, " ", form_str(RPL_METADATAUNSUBOK), me.name, source_p->name);
	for (int i = 0; i < parc; i++)
	{
		const char *key = parv[i];
		if (!metadata_key_valid(key))
		{
			sendto_one(source_p, ":%s WARN METADATA INVALID_KEY %s :Invalid key", me.name, sanitize_middle_param(key));
			continue;
		}

		count++;
		rb_dictionary_element *sub_elem = rb_dictionary_find(sub_index, key);

		if (sub_elem != NULL)
		{
			char *sub_key = (char *)sub_elem->key;
			rb_dlink_list *sub_list = sub_elem->data;
			if (client_subs != NULL)
				rb_dlinkFindDestroy(sub_key, client_subs);

			rb_dlinkFindDestroy(source_p, sub_list);
			if (rb_dlink_list_length(sub_list) == 0)
			{
				rb_free(sub_list);
				rb_dictionary_delete(sub_index, sub_key);
				rb_free(sub_key);
			}
		}

		send_multiline_item(source_p, "%s", key);
	}

	if (client_subs != NULL && rb_dlink_list_length(client_subs) == 0)
	{
		rb_free(client_subs);
		rb_dictionary_delete(client_index, source_p);
	}

	if (count)
		send_multiline_fini(source_p, NULL);
	else
		send_multiline_reset();
}

static void
me_mda(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* ENCAP * MDA <type> <targetTS> <keyTS> <target> <target2> <key> :<value> */
	struct MetadataEntry *entry = NULL;
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	const char *type = parv[1];
	time_t targetTS = atol(parv[2]);
	time_t keyTS = atol(parv[3]);
	const char *target = parv[4];
	const char *target2 = parv[5];
	const char *key = parv[6];
	const char *value = parv[7];

	if (strlen(type) != 1)
		return;

	switch (*type)
	{
	case 'U':
		target_p = find_client(target);
		if (target_p == NULL || target_p->tsinfo < targetTS)
			return;

		entry = get_user_metadata(target_p, key, false);
		break;
	case 'C':
		chptr = find_channel(target);
		if (chptr == NULL || chptr->channelts < targetTS)
			return;

		entry = get_channel_metadata(chptr, key, false);
		break;
	case 'M':
		chptr = find_channel(target);
		target_p = find_client(target2);
		if (chptr == NULL || target_p == NULL || chptr->channelts < targetTS)
			return;

		msptr = find_channel_membership(chptr, target_p);
		if (msptr == NULL)
			return;

		entry = get_member_metadata(msptr, key, false);
		break;
	default:
		return;
	}

	if (entry == NULL || entry->tsinfo != keyTS)
		return;

	set_metadata_value(entry, entry->setter, value, true);
	/* note: no notify_subs here because the spec lacks any support for such notifications */
}

static void
me_mdd(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* ENCAP * MDD <type> <targetTS> <keyTS> <target> <target2> :<keys...> */
	char *save;
	struct MetadataEntry *entry = NULL;
	struct Client *target_p = NULL;
	struct Channel *chptr = NULL;
	struct membership *msptr = NULL;
	const char *type = parv[1];
	time_t targetTS = atol(parv[2]);
	time_t keyTS = atol(parv[3]);
	const char *target = parv[4];
	const char *target2 = parv[5];
	const char *keys = parv[6];
	char buf[BUFSIZE];

	if (strlen(type) != 1)
		return;

	switch (*type)
	{
	case 'U':
		target_p = find_client(target);
		if (target_p == NULL || target_p->tsinfo < targetTS)
			return;
		break;
	case 'C':
		chptr = find_channel(target);
		if (chptr == NULL || chptr->channelts < targetTS)
			return;
		break;
	case 'M':
		chptr = find_channel(target);
		target_p = find_client(target2);
		if (chptr == NULL || target_p == NULL || chptr->channelts < targetTS)
			return;

		msptr = find_channel_membership(chptr, target_p);
		if (msptr == NULL)
			return;
		break;
	default:
		return;
	}

	rb_strlcpy(buf, keys, sizeof(buf));
	for (const char *key = rb_strtok_r(buf, " ", &save); key != NULL; key = rb_strtok_r(NULL, " ", &save))
	{
		if (*type == 'U')
			entry = get_user_metadata(target_p, key, false);
		else if (*type == 'C')
			entry = get_channel_metadata(chptr, key, false);
		else
			entry = get_member_metadata(msptr, key, false);

		if (entry == NULL || entry->tsinfo > keyTS)
			continue;

		entry->tsinfo = keyTS;
		entry->flags |= METADATA_FLAG_DELETED;
		notify_subs(source_p, entry);
	}
}

static void
me_mdi(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* ENCAP * MDI <type> <targetTS> <keyTS> <target> <target2> <key> <read> <write> +<flags> <setter> */
	struct MetadataEntry *entry = NULL;
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	const char *type = parv[1];
	time_t targetTS = atol(parv[2]);
	time_t keyTS = atol(parv[3]);
	const char *target = parv[4];
	const char *target2 = parv[5];
	const char *key = parv[6];
	const char *read = parv[7];
	const char *write = parv[8];
	const char *flags = parv[9];
	const char *setter = parv[10];

	if (strlen(type) != 1)
		return;

	switch (*type)
	{
	case 'U':
		target_p = find_client(target);
		if (target_p == NULL || target_p->tsinfo < targetTS)
			return;

		entry = get_user_metadata(target_p, key, false);
		break;
	case 'C':
		chptr = find_channel(target);
		if (chptr == NULL || chptr->channelts < targetTS)
			return;

		entry = get_channel_metadata(chptr, key, false);
		break;
	case 'M':
		chptr = find_channel(target);
		target_p = find_client(target2);
		if (chptr == NULL || target_p == NULL || chptr->channelts < targetTS)
			return;

		msptr = find_channel_membership(chptr, target_p);
		if (msptr == NULL)
			return;

		entry = get_member_metadata(msptr, key, false);
		break;
	default:
		return;
	}

	if (entry == NULL && entry->tsinfo != keyTS)
		return;

	rb_free(entry->setter);
	entry->setter = rb_strdup(setter);
	entry->flags = 0;

	if (strlen(read) == 1)
	{
		switch (*read)
		{
		case '*':
			entry->read = METADATA_ALLOW_ALL;
			break;
		case '#':
			entry->read = METADATA_ALLOW_CHANNEL;
			break;
		case '@':
			if (entry->type == METADATA_CHANNEL)
				entry->read = METADATA_ALLOW_OP;
			break;
		case '!':
			if (entry->type != METADATA_CHANNEL)
				entry->read = METADATA_ALLOW_SELF;
			break;
		case 'o':
			entry->read = METADATA_ALLOW_AUSPEX;
			break;
		default:
			break;
		}
	}

	if (strlen(write) == 1)
	{
		switch (*write)
		{
		case '@':
			if (entry->type == METADATA_CHANNEL)
				entry->write = METADATA_ALLOW_OP;
			break;
		case '!':
			if (entry->type != METADATA_CHANNEL)
				entry->write = METADATA_ALLOW_SELF;
			break;
		case 'o':
			entry->write = METADATA_ALLOW_AUSPEX;
			break;
		case 'S':
			entry->write = METADATA_ALLOW_SERVICES;
			break;
		default:
			break;
		}
	}

	if (*flags == '+')
	{
		for (int i = 1; flags[i] != '\0'; i++)
		{
			if (flags[i] == 'x')
				entry->flags |= METADATA_FLAG_EXCLUDE;
		}
	}

	notify_subs(source_p, entry);
}

static void
me_mds(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* ENCAP * MDS <type> <targetTS> <keyTS> <target> <target2> <key> :<value> */
	struct MetadataEntry *entry = NULL;
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	const char *type = parv[1];
	time_t targetTS = atol(parv[2]);
	time_t keyTS = atol(parv[3]);
	const char *target = parv[4];
	const char *target2 = parv[5];
	const char *key = parv[6];
	const char *value = parv[7];

	if (strlen(type) != 1)
		return;

	switch (*type)
	{
	case 'U':
		target_p = find_client(target);
		if (target_p == NULL || target_p->tsinfo < targetTS)
			return;

		entry = get_user_metadata(target_p, key, true);
		break;
	case 'C':
		chptr = find_channel(target);
		if (chptr == NULL || chptr->channelts < targetTS)
			return;

		entry = get_channel_metadata(chptr, key, true);
		break;
	case 'M':
		chptr = find_channel(target);
		target_p = find_client(target2);
		if (chptr == NULL || target_p == NULL || chptr->channelts < targetTS)
			return;

		msptr = find_channel_membership(chptr, target_p);
		if (msptr == NULL)
			return;

		entry = get_member_metadata(msptr, key, true);
		break;
	default:
		return;
	}

	if (!IsMetadataNew(entry) && entry->tsinfo > keyTS)
		return;

	entry->tsinfo = keyTS;
	/* the key is not readable until ENCAP MDI is sent */
	entry->read = METADATA_ALLOW_SERVICES;
	entry->write = METADATA_ALLOW_SERVICES;
	set_metadata_value(entry, entry->setter, value, false);
}

static int
metadata_cmd_search(const char *command, const struct metadata_cmd *entry)
{
	return irccmp(command, entry->cmd);
}

static void
m_metadata(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (!enable_client_command || !IsClientCapable(source_p, CLICAP_BATCH | CLICAP_METADATA))
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "METADATA");
		return;
	}

	struct metadata_cmd *cmd = bsearch(parv[2], metadata_cmdlist,
		sizeof(metadata_cmdlist) / sizeof(struct metadata_cmd),
		sizeof(struct metadata_cmd), (bqcmp)metadata_cmd_search);

	if (cmd == NULL)
	{
		sendto_one(source_p, ":%s FAIL METADATA INVALID_PARAMS %s :Invalid subcommand",
			me.name, sanitize_middle_param(parv[2]));
		return;
	}

	if (parc < cmd->min_para)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "METADATA");
		return;
	}

	cmd->func(msgbuf, source_p, parv[1], parc - 3, parv + 3);
}
