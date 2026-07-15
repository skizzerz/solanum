/*
 * Solanum: a slightly advanced ircd
 * m_token.c: Implementation for the draft/authtoken specification
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
#include "client.h"
#include "modules.h"
#include "msgbuf.h"
#include "newconf.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"

#define SERVICE_CLAIM_ACCOUNT     0x01
#define SERVICE_CLAIM_MEMBER_OF   0x02
#define SERVICE_CLAIM_NAME        0x04
#define SERVICE_CLAIM_OPERATOR_OF 0x08
#define SERVICE_CLAIM_ROLE        0x10
#define SERVICE_CLAIM_SCOPE       0x20

#define SERVICE_FLAG_ORPHANED 0x01

/* buffer size of an authtoken: 3 bytes for SID, 32 random hex chars, trailing null byte */
#define AUTHTOKEN_LEN 36
/* time in seconds an authtoken is valid for (15 minutes) */
#define AUTHTOKEN_EXPIRY 900

struct AuthService
{
	char *key;
	char *url;
	uint32_t claims;
	uint32_t flags;
};

struct AuthToken
{
	const struct AuthService *service;
	struct Client *client;
	rb_dlink_node *node;
	time_t expires;
	char token[AUTHTOKEN_LEN];
};

static uint64_t CLICAP_AUTHTOKEN = 0;
static rb_dictionary *services = NULL;
static rb_dictionary *tokens = NULL;

static const char token_desc[] = "Support for the TOKEN command and draft/authtoken spec";

static int modinit(void);
static void moddeinit(void);
static void m_token(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_token(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static int conf_begin_authservice(struct TopConf *);
static int conf_end_authservice(struct TopConf *);
static void conf_set_claims(void *);
static void conf_set_flags(void *);
static void conf_set_url(void *);
static void free_authservice_elem(rb_dictionary_element *, void *);
static void free_authservice(struct AuthService *);
static void free_token_elem(rb_dictionary_element *, void *);
static void free_token(struct AuthToken *);
static void token_burst(void *);
static void token_read_conf(void *);
static void token_rehash(void *);

/*
authservice "SERVICENAME" {
	url = "https://example.com";
	claims = account, member_of, name, operator_of, role, scope;
	flags = ;
	scope = channel | user | none; (default none)
	# criteria can be here as well to apply to the service instead of a role

	# repeating section for role definitions
	# listing multiple conditions creates a conjunction across those conditions
	# listing a condition multiple times creates a disjunction for that condition
	role = "rolename";
	privset = "privset"; # must have listed privset to match
	privs = priv:name, priv:name; # must have ALL privs listed to match (oper privs or iline flags)
	umodes = "+iz"; # must have ALL umodes listed to match
	hostmask = "*!*@*"; # nick!user@host mask to match (xline wildcards and CIDR for IPs allowed, matches against spoofs/realhost/IP)
	realname = "*"; # gecos mask to match (xline wildcards and spaces allowed)
	account = "*"; # account mask to match (xline wildcards allowed)
	prefix = "@"; # prefix character to match (+ or @ channel status, only valid if scope = channel)
};
*/

struct ConfEntry conf_authservice_table[] = {
	{ "url", CF_QSTRING, conf_set_url, 0, NULL },
	{ "claims", CF_STRING | CF_FLIST, conf_set_claims, 0, NULL },
	{ "flags", CF_STRING | CF_FLIST, conf_set_flags, 0, NULL },
	{ "\0",	0, NULL, 0, NULL }
};

struct Message token_msgtab = {
	"TOKEN", 0, 0, 0, 0,
	{ {m_token, 2}, {m_token, 2}, mg_ignore, mg_ignore, {me_token, 3}, {m_token, 2} }
};

/* TODO: hook to clear a client's tokens when they exit */
mapi_hfn_list_av1 token_hfn_list[] = {
	{ "conf_read_start", token_read_conf },
	{ "rehash", token_rehash },
	{ "user_welcome", token_burst },
	{ NULL, NULL }
};

mapi_clist_av1 token_clist[] = { &token_msgtab, NULL };

mapi_cap_list_av2 token_cap_list[] = {
	{ MAPI_CAP_CLIENT, "draft/authtoken", NULL, &CLICAP_AUTHTOKEN },
	{ 0, NULL, NULL, NULL }
};

DECLARE_MODULE_AV2(token, modinit, moddeinit, token_clist, NULL, token_hfn_list, token_cap_list, NULL, token_desc);

static int
modinit(void)
{
	/* TODO: event to purge expired tokens */
	services = rb_dictionary_create("authtoken services", rb_strcasecmp);
	tokens = rb_dictionary_create("authtokens", rb_strcmp);
	add_top_conf("authservice", conf_begin_authservice, conf_end_authservice, conf_authservice_table);
	return 1;
}

static void
moddeinit(void)
{
	rb_dictionary_destroy(services, free_authservice_elem, NULL);
	rb_dictionary_destroy(services, free_token_elem, NULL);
	remove_top_conf("authservice");
}

static void
free_authservice_elem(rb_dictionary_element *el, void *unused)
{
	free_authservice(el->data);
}

/* Note: This *DOES NOT* remove the service from the services dict; do that first before calling this! */
static void free_authservice(struct AuthService *service)
{
	rb_free(service->key);
	rb_free(service->url);
	rb_free(service);
}

static void
free_token_elem(rb_dictionary_element *el, void *unused)
{
	free_token(el->data);
}

/* Note: This *DOES NOT* remove the token from the tokens dict; do that first before calling this! */
static void
free_token(struct AuthToken *token)
{
	rb_dlinkDestroy(token->node, &token->client->localClient->auth_tokens);
	rb_free(token);
}

static void
token_burst(void *data)
{
	struct Client *client_p = data;
	rb_dictionary_element *el;
	rb_dictionary_iter state;
	struct MsgTag tag = { "batch", "servicelist", CLICAP_BATCH };

	if (IsClientCapable(client_p, CLICAP_AUTHTOKEN | CLICAP_BATCH))
	{
		if (rb_dictionary_size(services) == 0)
		{
			sendto_one(client_p, ":%s NOTE TOKEN NO_SERVICES :No services are defined for this network.", me.name);
			return;
		}

		sendto_one(client_p, ":%s BATCH +servicelist draft/authtoken *", me.name);

		RB_DICTIONARY_FOREACH(el, &state, services)
		{
			struct AuthService *service = el->data;
			sendto_one_tags(client_p, NOCAPS, NOCAPS, 1, &tag,
				":%s TOKEN SERVICE %s %s", me.name, service->key, service->url);
		}

		sendto_one(client_p, ":%s BATCH -servicelist", me.name);
	}
}

/* Mark all existing services as orphaned when we start reading ircd.conf.
 * If a service is defined by the new conf, the flag is unset by conf_begin_authservice.
 * If a service isn't defined, then token_rehash will know to send TOKEN DEL notifications for it.
 */
static void
token_read_conf(void *unused)
{
	rb_dictionary_element *el;
	rb_dictionary_iter state;

	RB_DICTIONARY_FOREACH(el, &state, services)
	{
		struct AuthService *service = el->data;
		service->flags |= SERVICE_FLAG_ORPHANED;
	}
}

static void
token_rehash(void *unused)
{
	rb_dictionary_element *el;
	rb_dictionary_iter state;

	RB_DICTIONARY_FOREACH(el, &state, services)
	{
		struct AuthService *service = el->data;
		if (service->flags & SERVICE_FLAG_ORPHANED)
		{
			sendto_local_clients_with_capability(CLICAP_AUTHTOKEN, ":%s TOKEN DEL %s",
				me.name, service->key);
			/* and delete it entirely since otherwise we'd send out duplicated DELs on the next rehash */
			rb_dictionary_delete(services, service->key);
			free_authservice(service);
		}
	}
}

static int
conf_begin_authservice(struct TopConf *tc)
{

}

static int
conf_end_authservice(struct TopConf *tc)
{

}

static void
conf_set_claims(void *value)
{

}

static void
conf_set_flags(void *value)
{

}

static void
conf_set_url(void *value)
{

}

static void
m_token(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{

}

/* ENCAP TOKEN V <service> <token>; source_p is the user issuing TOKEN VALIDATE on the remote server */
static void
me_token(struct MsgBuf *msgbuf, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct AuthToken *token = NULL;
	char batch[BATCH_ID_LEN];

	switch (*parv[1])
	{
	case 'V':
		token = rb_dictionary_retrieve(tokens, parv[3]);
		if (token == NULL || strcasecmp(parv[1], token->service->key) != 0 || token->expires <= rb_current_time())
		{
			sendto_one(source_p, ":%s ENCAP %s TOKEN I %s", me.id, source_p->servptr->name, use_id(source_p));
			return;
		}

		generate_batch_id(batch, sizeof(batch));
		sendto_one(source_p, ":%s ENCAP %s TOKEN + %s %s", me.id, source_p->servptr->name, use_id(source_p), batch);
		sendto_one(source_p, ":%s ENCAP %s TOKEN - %s %s", me.id, source_p->servptr->name, use_id(source_p), batch);
		break;
	}
}
