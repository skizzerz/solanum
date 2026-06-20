/*
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

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "batch.h"
#include "tap/basic.h"

#include "ircd_util.h"
#include "client_util.h"
#include "hash.h"
#include "hostmask.h"

#include "send.h"
#include "s_serv.h"
#include "metadata.h"
#include "monitor.h"
#include "newconf.h"
#include "s_conf.h"

#define MSG "%s:%d (%s)", __FILE__, __LINE__, __FUNCTION__
#define LONG_VALUE_50 "12345678901234567890123456789012345678901234567890"
#define LONG_VALUE_100 LONG_VALUE_50 LONG_VALUE_50
#define LONG_VALUE_200 LONG_VALUE_100 LONG_VALUE_100
#define LONG_VALUE_400 LONG_VALUE_200 LONG_VALUE_200

#define SYNCLATER_AUTO "Automatic metadata is not supported for this target, please sync manually."
#define SYNCLATER_RATE_LIMIT "This command could not be completed because it has been used recently, and is rate-limited."
#define SYNCLATER_PENDING "A SYNC operation is currently in progress, try again after it has completed."

uint64_t CLICAP_METADATA;

static struct Client *user;
static struct Client *server;
static struct Client *remote;
static struct Client *server2;
static struct Client *remote2;
static struct Client *server3;
static struct Client *remote3;
static struct Channel *channel;
static struct Channel *lchannel;

static struct Client *local_chan_o;
static struct Client *local_chan_ov;
static struct Client *local_chan_v;
static struct Client *local_chan_p;
static struct Client *local_no_chan;

static struct Client *remote_chan_o;
static struct Client *remote_chan_ov;
static struct Client *remote_chan_v;
static struct Client *remote_chan_p;

static struct Client *remote2_chan_p;
static struct Client *remote2_no_chan;

static char batch1[BATCH_ID_LEN];
static char batch2[BATCH_ID_LEN];
static char batch3[BATCH_ID_LEN];
static char batch4[BATCH_ID_LEN];
static char batch5[BATCH_ID_LEN];
static char batch6[BATCH_ID_LEN];
static char batch7[BATCH_ID_LEN];
static char batch8[BATCH_ID_LEN];

static void standard_init(void)
{
	user = make_local_person_id(TEST_NICK, TEST_ID);
	server = make_remote_server_full(&me, TEST_SERVER_NAME, TEST_SERVER_ID);
	remote = make_remote_person_id(server, TEST_REMOTE_NICK, TEST_REMOTE_ID);
	server2 = make_remote_server_full(&me, TEST_SERVER2_NAME, TEST_SERVER2_ID);
	remote2 = make_remote_person_id(server2, TEST_REMOTE2_NICK, TEST_REMOTE2_ID);
	server3 = make_remote_server_full(&me, TEST_SERVER3_NAME, TEST_SERVER3_ID);
	remote3 = make_remote_person_id(server3, TEST_REMOTE3_NICK, TEST_REMOTE3_ID);

	local_chan_o = make_local_person_id("LChanOp", TEST_ME_ID "90001");
	local_chan_ov = make_local_person_id("LChanOpVoice", TEST_ME_ID "90002");
	local_chan_v = make_local_person_id("LChanVoice", TEST_ME_ID "90003");
	local_chan_p = make_local_person_id("LChanPeon", TEST_ME_ID "90004");
	local_no_chan = make_local_person_id("LNoChan", TEST_ME_ID "90005");

	remote_chan_o = make_remote_person_id(server, "RChanOp", TEST_SERVER_ID "90101");
	remote_chan_ov = make_remote_person_id(server, "RChanOpVoice", TEST_SERVER_ID "90102");
	remote_chan_v = make_remote_person_id(server, "RChanVoice", TEST_SERVER_ID "90103");
	remote_chan_p = make_remote_person_id(server, "RChanPeon", TEST_SERVER_ID "90104");

	remote2_chan_p = make_remote_person_id(server2, "R2ChanPeon", TEST_SERVER2_ID "90204");
	remote2_no_chan = make_remote_person_id(server2, "R2NoChan", TEST_SERVER2_ID "90205");

	channel = make_channel();

	add_user_to_channel(channel, local_chan_o, CHFL_CHANOP);
	add_user_to_channel(channel, local_chan_ov, CHFL_CHANOP | CHFL_VOICE);
	add_user_to_channel(channel, local_chan_v, CHFL_VOICE);
	add_user_to_channel(channel, local_chan_p, CHFL_PEON);

	add_user_to_channel(channel, remote_chan_o, CHFL_CHANOP);
	add_user_to_channel(channel, remote_chan_ov, CHFL_CHANOP | CHFL_VOICE);
	add_user_to_channel(channel, remote_chan_v, CHFL_VOICE);
	add_user_to_channel(channel, remote_chan_p, CHFL_PEON);

	add_user_to_channel(channel, remote2_chan_p, CHFL_PEON);

	lchannel = get_or_create_channel(&me, "&test", NULL);

	add_user_to_channel(lchannel, user, CHFL_PEON);
	add_user_to_channel(lchannel, remote, CHFL_PEON);
	add_user_to_channel(lchannel, remote2, CHFL_PEON);
	add_user_to_channel(lchannel, remote3, CHFL_PEON);

	/* for consistent batch IDs */
	srand(0);
}

static void init_large_metadata(void)
{
	struct MetadataEntry *entry;
	add_user_to_channel(channel, user, CHFL_PEON);
	struct membership *msptr = find_channel_membership(channel, user);
	char key[8];

	attach_conf(user, find_conf_by_address(user->host, user->sockhost, NULL,
		(struct sockaddr *)&user->localClient->ip, CONF_CLIENT, GET_SS_FAMILY(&user->localClient->ip),
		user->username, user->localClient->auth_user));

	for (int i = 1; i <= 99; i++)
	{
		snprintf(key, sizeof(key), "test%02d", i);
		entry = get_user_metadata(user, key, true);
		set_metadata_value(entry, "test", LONG_VALUE_200, false);
		entry->read = METADATA_ALLOW_ALL;
		entry->write = METADATA_ALLOW_SELF;
		entry = get_user_metadata(local_chan_p, key, true);
		set_metadata_value(entry, "test", LONG_VALUE_200, false);
		entry->read = METADATA_ALLOW_ALL;
		entry->write = METADATA_ALLOW_SELF;
		entry = get_channel_metadata(channel, key, true);
		set_metadata_value(entry, "test", LONG_VALUE_200, false);
		entry->read = METADATA_ALLOW_CHANNEL;
		entry->write = METADATA_ALLOW_OP;
		entry = get_member_metadata(msptr, key, true);
		set_metadata_value(entry, "test", LONG_VALUE_200, false);
		entry->read = METADATA_ALLOW_CHANNEL;
		entry->write = METADATA_ALLOW_SELF;
	}
}

static void standard_free(void)
{
	remove_remote_person(remote2_chan_p);
	remove_remote_person(remote2_no_chan);

	remove_remote_person(remote_chan_o);
	remove_remote_person(remote_chan_ov);
	remove_remote_person(remote_chan_v);
	remove_remote_person(remote_chan_p);

	remove_local_person(local_chan_o);
	remove_local_person(local_chan_ov);
	remove_local_person(local_chan_v);
	remove_local_person(local_chan_p);
	remove_local_person(local_no_chan);

	remove_remote_person(remote3);
	remove_remote_server(server3);
	remove_remote_person(remote2);
	remove_remote_server(server2);
	remove_remote_person(remote);
	remove_remote_server(server);

	if (user != NULL)
		remove_local_person(user);
}

static void make_local_person_auspex(struct Client *oper)
{
	make_local_person_oper(oper);
	oper->snomask = 0;
	oper->user->privset = privilegeset_get("auspex");
}

static void metadata_key_usage_tracking(void)
{
	standard_init();

	is_int(0, rb_dictionary_size(metadata_key_usage), MSG);
	struct MetadataEntry *entry = get_user_metadata(user, "test", true);
	uintptr_t key_ref = (uintptr_t)entry->key;
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_int(1, (intptr_t)rb_dictionary_retrieve(metadata_key_usage, "test"), MSG);
	entry = get_channel_metadata(channel, "test", true);
	is_hex(key_ref, (uintptr_t)entry->key, MSG);
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_int(2, (intptr_t)rb_dictionary_retrieve(metadata_key_usage, "test"), MSG);
	entry = get_user_metadata(user, "test2", false);
	is_hex(0, (uintptr_t)entry, MSG);
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_int(0, (intptr_t)rb_dictionary_retrieve(metadata_key_usage, "test2"), MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	struct membership *msptr = find_channel_membership(channel, user);
	entry = get_member_metadata(msptr, "test", true);
	is_hex(key_ref, (uintptr_t)entry->key, MSG);
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_int(3, (intptr_t)rb_dictionary_retrieve(metadata_key_usage, "test"), MSG);

	standard_free();
	rb_run_one_event_for_tests("free_exited_clients");

	/* freeing metadata should call decr_key which should remove the entry from metadata_key_usage */
	is_int(0, rb_dictionary_size(metadata_key_usage), MSG);
	is_int(0, (intptr_t)rb_dictionary_retrieve(metadata_key_usage, "test"), MSG);
}

static void metadata_sub_tracking(void)
{
	standard_init();

	rb_dictionary *sub_index = rb_dictionary_get_for_tests("metadata sub index");
	rb_dictionary *client_index = rb_dictionary_get_for_tests("metadata client index");
	SetClientCap(local_chan_p, CLICAP_METADATA | CLICAP_BATCH);
	SetClientCap(local_chan_v, CLICAP_METADATA | CLICAP_BATCH);

	is_int(0, rb_dictionary_size(sub_index), MSG);
	is_int(0, rb_dictionary_size(client_index), MSG);
	client_util_parse(local_chan_p, "METADATA * SUB test1 test2");
	is_int(2, rb_dictionary_size(sub_index), MSG);
	is_int(1, rb_dictionary_size(client_index), MSG);
	is_int(2, rb_dlink_list_length((rb_dlink_list *)rb_dictionary_retrieve(client_index, local_chan_p)), MSG);
	client_util_parse(local_chan_v, "METADATA * SUB test1 test3");
	is_int(3, rb_dictionary_size(sub_index), MSG);
	is_int(2, rb_dictionary_size(client_index), MSG);
	is_int(2, rb_dlink_list_length((rb_dlink_list *)rb_dictionary_retrieve(client_index, local_chan_v)), MSG);

	/* the key of sub_index should be the same pointer as the values of client_index */
	rb_dictionary_element *elem = rb_dictionary_find(sub_index, "test1");
	is_bool(true, rb_dlinkFind((void *)elem->key, rb_dictionary_retrieve(client_index, local_chan_p)) != NULL, MSG);
	is_bool(true, rb_dlinkFind((void *)elem->key, rb_dictionary_retrieve(client_index, local_chan_v)) != NULL, MSG);

	client_util_parse(local_chan_v, "METADATA * UNSUB test3");
	is_int(2, rb_dictionary_size(sub_index), MSG);
	is_int(2, rb_dictionary_size(client_index), MSG);
	is_int(1, rb_dlink_list_length((rb_dlink_list *)rb_dictionary_retrieve(client_index, local_chan_v)), MSG);

	standard_free();

	is_int(0, rb_dictionary_size(sub_index), MSG);
	is_int(0, rb_dictionary_size(client_index), MSG);
}

static void set_metadata_value__new(void)
{
	standard_init();

	struct MetadataEntry *entry = get_user_metadata(user, "test", true);
	set_metadata_value(entry, "test", "value", false);
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_string("test", entry->key, MSG);
	is_string("test", entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value", entry->values.head->data, MSG);

	standard_free();
}

static void set_metadata_value__append(void)
{
	standard_init();

	struct MetadataEntry *entry = get_user_metadata(user, "test", true);
	set_metadata_value(entry, "test", "value", false);
	set_metadata_value(entry, "invalid", "value2", true);
	is_int(1, rb_dictionary_size(metadata_key_usage), MSG);
	is_string("test", entry->key, MSG);
	is_string("test", entry->setter, MSG);
	is_int(2, rb_dlink_list_length(&entry->values), MSG);
	is_string("value", entry->values.head->data, MSG);
	is_string("value2", entry->values.tail->data, MSG);

	standard_free();
}

static void metadata_get__other(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_user_metadata(local_chan_p, "test", true);
	set_metadata_value(entry, "test", "value", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;

	client_util_parse(user, "METADATA LChanPeon GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test * :value" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test2 :Key not set" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test3 :Key not set" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test4 :Key not set" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test5 :Key not set" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA LChanPeon GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test * :value" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test3 :Key not set" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test4 :Key not set" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test5 :Key not set" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA LChanPeon GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test * :value" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test4 :Key not set" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test5 :Key not set" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	/* auspex cannot "read down" to other levels and we no longer share a channel */
	remove_user_from_channel(find_channel_membership(channel, user));
	client_util_parse(user, "METADATA LChanPeon GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch4);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test * :value" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test2 :Key not set" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test4 :Key not set" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test5 :Key not set" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	/* operspy can read everything */
	client_util_parse(user, "METADATA !LChanPeon GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch5);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test * :value" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test4 ! :value4" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s LChanPeon test5 :Key not set" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_get__self(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_user_metadata(user, "test", true);
	set_metadata_value(entry, "test", "value", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(user, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(user, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(user, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;

	/* leave all channels */
	remove_user_from_channels(user);

	client_util_parse(user, "METADATA " TEST_NICK " GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_NICK " GET test test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 o :value3" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_get__channel(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_channel_metadata(channel, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_channel_metadata(channel, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_channel_metadata(channel, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA " TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test2 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test4 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_VOICE);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test4 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test4 :Key not set" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch4, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	remove_user_from_channel(msptr);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch5, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test2 :Key not set" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA !" TEST_CHANNEL " GET test1 test2 test3 test4 test5");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch6, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test5 :Key not set" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch6);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_get__member(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	SetClientCap(local_chan_p, CLICAP_METADATA | CLICAP_BATCH);

	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA " TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test2 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test3 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test4 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test3 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test4 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test3 :Key not set" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	msptr = find_channel_membership(channel, user);
	remove_user_from_channel(msptr);
	client_util_parse(user, "METADATA " TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch4, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test2 :Key not set" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test3 :Key not set" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA !" TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch5, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test3 ! :value3" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	client_util_parse(local_chan_p, "METADATA " TEST_CHANNEL " GET member/LChanPeon/test1 member/LChanPeon/test2 member/LChanPeon/test3 member/LChanPeon/test4");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch6, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test1 * :value1" CRLF, batch6, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test2 # :value2" CRLF, batch6, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test3 ! :value3" CRLF, batch6, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 LChanPeon %s member/LChanPeon/test4 :Key not set" CRLF, batch6, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch6);
	is_client_sendq(expected, local_chan_p, MSG);

	client_util_parse(user, "METADATA !" TEST_CHANNEL " GET member/LChanPeon/test6 member/NoSuchUser/test1 member/" TEST_NICK "/test1 member/LNoChan/test1");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch7, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LChanPeon/test6 :Key not set" CRLF, batch7, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY member/NoSuchUser/test1 :No such nick" CRLF, batch7, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/%s/test1 :Key not set" CRLF, batch7, me.name, user->name, channel->chname, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s member/LNoChan/test1 :Key not set" CRLF, batch7, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch7);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_get__nopara(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * GET");
	is_client_sendq(":" TEST_ME_NAME " 461 " TEST_NICK " METADATA :Not enough parameters" CRLF, user, MSG);

	standard_free();
}

static void metadata_get__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * GET");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_get__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * GET");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_get__invalid_key(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* denied-* is blocked in conf */
	client_util_parse(user, "METADATA * GET INVALID $invalid denied-foo member/LChanPeon/test ::");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY INVALID :Invalid key" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY $invalid :Invalid key" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY denied-foo :Invalid key" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	/* member/ keys are not valid on non-channel targets */
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY member/LChanPeon/test :Invalid key" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	/* key is ":" which isn't a valid middle parameter, so it gets subbed out with "*" */
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY * :Invalid key" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * GET :foo bar");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY * :Invalid key" CRLF, batch2, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " GET member/LChanPeon/extra/slash member/NotAUser/test");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata " TEST_CHANNEL CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY member/LChanPeon/extra/slash :Invalid key" CRLF, batch3, me.name);
	is_client_sendq_one(expected, user, MSG);
	/* slightly different error message if the nickname portion doesn't exist */
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY member/NotAUser/test :No such nick" CRLF, batch3, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * GET verylongkey" LONG_VALUE_100 " :");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch4, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY verylongkey" LONG_VALUE_100 " :Invalid key" CRLF, batch4, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA INVALID_KEY * :Invalid key" CRLF, batch4, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_get__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ GET test");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser GET test");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan GET test");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :No such channel" CRLF, user, MSG);

	/* attempted spy without oper:spy privs */
	client_util_parse(user, "METADATA !LChanPeon GET test");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !LChanPeon :No such nick" CRLF, user, MSG);

	standard_free();
}

static void metadata_list__other(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	ClearInvisible(local_chan_p);

	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	/* some extra member entries for a different target, to ensure we don't mistakenly reveal them */
	msptr = find_channel_membership(channel, local_chan_v);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_ALL;

	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	/* auspex cannot "read down" to other levels and we no longer share a channel */
	remove_user_from_channel(find_channel_membership(channel, user));
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch4);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	/* operspy can read everything */
	client_util_parse(user, "METADATA !LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch5);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test4 ! :value4" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test3 ! :value3" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_list__other_invisible(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	SetInvisible(local_chan_p);

	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	/* some extra member entries for a different target, to ensure we don't mistakenly reveal them */
	msptr = find_channel_membership(channel, local_chan_v);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_ALL;

	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	/* auspex cannot "read down" to other levels and we no longer share a channel */
	remove_user_from_channel(find_channel_membership(channel, user));
	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch4);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	/* operspy can read everything */
	client_util_parse(user, "METADATA !LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch5);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test2 # :value2" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test4 ! :value4" CRLF, batch5, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test3 ! :value3" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_list__self(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_user_metadata(user, "test", true);
	set_metadata_value(entry, "test", "value", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(user, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(user, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(user, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;

	/* leave all channels */
	remove_user_from_channels(user);

	client_util_parse(user, "METADATA " TEST_NICK " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_NICK " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test * :value" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 o :value3" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 ! :value4" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_list__channel(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	SetClientCap(local_chan_p, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_channel_metadata(channel, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_channel_metadata(channel, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_channel_metadata(channel, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_v);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_ALL;

	/* for channel + member metadata, the channel metadata is listed first, then member in alphabetical order by nick */

	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_VOICE);
	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;
	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch4, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	remove_user_from_channel(msptr);
	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch5, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch5, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA !" TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch6, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test2 # :value2" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test4 o :value4" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test2 # :value2" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test3 ! :value3" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test4 o :value4" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test2 * :value2" CRLF, batch6, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch6);
	is_client_sendq(expected, user, MSG);

	client_util_parse(local_chan_p, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch7, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s test1 * :value1" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s test2 # :value2" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test1 * :value1" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test2 # :value2" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test3 ! :value3" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanVoice/test1 # :value1" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanVoice/test2 * :value2" CRLF, batch7, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch7);
	is_client_sendq(expected, local_chan_p, MSG);

	standard_free();
}

static void metadata_list__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * GET");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_list__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * GET");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_list__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ LIST");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser LIST");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan LIST");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :No such channel" CRLF, user, MSG);

	/* attempted spy without oper:spy privs */
	client_util_parse(user, "METADATA !LChanPeon LIST");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !LChanPeon :No such nick" CRLF, user, MSG);

	standard_free();
}

static void metadata_list__large(void)
{
	char expected[BUFSIZE];
	char key[32];
	int refills = 0;

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH | CLICAP_LABELED_RESPONSE);

	client_util_parse(user, "@label=foo METADATA * LIST");
	snprintf(expected, sizeof(expected), "@label=foo :%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	for (int i = 1; i <= 99; i++)
	{
		snprintf(key, sizeof(key), "test%02d", i);
		snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s %s * :" LONG_VALUE_200 CRLF, batch1, me.name, user->name, user->name, key);
		is_client_sendq_one(expected, user, MSG);

		if (rb_linebuf_len(&user->localClient->buf_sendq) == 0 && user->localClient->metadata_data != NULL)
		{
			rb_run_one_event_for_tests("metadata_iterate_clients");
			if (rb_linebuf_len(&user->localClient->buf_sendq) == 0)
			{
				ok(0, "metadata_iterate_clients failed; " MSG);
				return;
			}

			refills++;
		}
	}

	for (int i = 1; i <= 99; i++)
	{
		snprintf(key, sizeof(key), "member/%s/test%02d", user->name, i);
		snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s %s # :" LONG_VALUE_200 CRLF, batch1, me.name, user->name, channel->chname, key);
		is_client_sendq_one(expected, user, MSG);

		if (rb_linebuf_len(&user->localClient->buf_sendq) == 0 && user->localClient->metadata_data != NULL)
		{
			rb_run_one_event_for_tests("metadata_iterate_clients");
			if (rb_linebuf_len(&user->localClient->buf_sendq) == 0)
			{
				ok(0, "metadata_iterate_clients failed; " MSG);
				return;
			}

			refills++;
		}
	}

	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);
	ok(refills > 0, MSG);

	standard_free();
}

static void metadata_list__large_user_exit(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	/* this should trip ASAN (and probably cause a crash even on non-ASAN builds)
	 * if the client wasn't fully cleaned up */
	remove_local_person(user);
	rb_run_one_event_for_tests("free_exited_clients");
	rb_run_one_event_for_tests("metadata_iterate_clients");

	user = NULL;
	standard_free();
}

static void metadata_list__large_target_exit(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	remove_user_from_channels(user);

	client_util_parse(user, "METADATA LChanPeon LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	remove_local_person(local_chan_p);
	rb_run_one_event_for_tests("metadata_iterate_clients");
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);

	standard_free();
}

static void metadata_list__large_channel_part(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	remove_user_from_channel(find_channel_membership(channel, user));
	rb_run_one_event_for_tests("metadata_iterate_clients");

	/* all channel/member metadata in init_large_metadata() is METADATA_ALLOW_CHANNEL for read perms,
	 * meaning leaving the channel denies access to all remaining keys; as such expect end of batch here */
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);

	standard_free();
}

static void metadata_list__large_channel_destroy(void)
{
	char expected[BUFSIZE];
	rb_dlink_node *ptr, *nptr;

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA " TEST_CHANNEL " LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	/* empty the channel, which destroys it */
	RB_DLINK_FOREACH_SAFE(ptr, nptr, channel->members.head)
	{
		struct membership *msptr = ptr->data;
		remove_user_from_channel(msptr);
	}

	rb_run_one_event_for_tests("metadata_iterate_clients");
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);

	standard_free();
}

static void metadata_list__large_abort(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * LIST");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	/* sending a followup LIST aborts the first */
	client_util_parse(user, "METADATA * LIST");
	snprintf(expected, sizeof(expected), "@batch=%s :%s FAIL METADATA ABORTED LIST :LIST aborted" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);

	standard_free();
}

static void metadata_set__self(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];
	char hostmask[USERHOST_REPLYLEN];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	snprintf(hostmask, sizeof(hostmask), "%s!%s@%s", user->name, user->username, user->host);

	client_util_parse(user, "METADATA * SET test value");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s test * :value" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "test", false);
	is_string("test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_ALL, entry->read, MSG);
	is_int(METADATA_ALLOW_SELF, entry->write, MSG);
	is_int(0, entry->flags, MSG);

	client_util_parse(user, "METADATA * SET test :");
	snprintf(expected, sizeof(expected), ":%s 766 %s %s test :Key not set" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "test", false);
	is_int(METADATA_FLAG_DELETED, entry->flags, MSG);

	client_util_parse(user, "METADATA " TEST_NICK " SET test :value with spaces");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s test * :value with spaces" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "test", false);
	is_int(0, entry->flags, MSG);ok(entry != NULL, MSG);

	client_util_parse(user, "METADATA * SET test");
	snprintf(expected, sizeof(expected), ":%s 766 %s %s test :Key not set" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "test", false);
	is_int(METADATA_FLAG_DELETED, entry->flags, MSG);

	client_util_parse(user, "METADATA * SET private/test value2");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION %s private/test :You do not have permission to set private/test on %s" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "private/test", false);
	is_hex(0, (uintptr_t)entry, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA * SET private/test value2");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s private/test o :value2" CRLF, me.name, user->name, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_user_metadata(user, "private/test", false);
	is_string("private/test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value2", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->read, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->write, MSG);
	is_int(METADATA_FLAG_EXCLUDE, entry->flags, MSG);

	standard_free();
}

static void metadata_set__channel(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];
	char hostmask[USERHOST_REPLYLEN];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	snprintf(hostmask, sizeof(hostmask), "%s!%s@%s", user->name, user->username, user->host);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET test value1");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION %s test :You do not have permission to set test on %s" CRLF, me.name, channel->chname, channel->chname);
	is_client_sendq(expected, user, MSG);
	is_hex(0, (uintptr_t)get_channel_metadata(channel, "test", false), MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SET test value1");
	is_client_sendq(expected, user, MSG);
	is_hex(0, (uintptr_t)get_channel_metadata(channel, "test", false), MSG);

	msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;
	client_util_parse(user, "METADATA " TEST_CHANNEL " SET test value1");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s test # :value1" CRLF, me.name, user->name, channel->chname);
	is_client_sendq(expected, user, MSG);
	entry = get_channel_metadata(channel, "test", false);
	is_string("test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value1", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_CHANNEL, entry->read, MSG);
	is_int(METADATA_ALLOW_OP, entry->write, MSG);
	is_int(0, entry->flags, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET test :");
	snprintf(expected, sizeof(expected), ":%s 766 %s %s test :Key not set" CRLF, me.name, user->name, channel->chname);
	is_client_sendq(expected, user, MSG);
	entry = get_channel_metadata(channel, "test", false);
	is_int(METADATA_FLAG_DELETED, entry->flags, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET private/test value2");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION %s private/test :You do not have permission to set private/test on %s" CRLF, me.name, channel->chname, channel->chname);
	is_client_sendq(expected, user, MSG);
	is_hex(0, (uintptr_t)get_channel_metadata(channel, "private/test", false), MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SET private/test value2");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s private/test o :value2" CRLF, me.name, user->name, channel->chname);
	is_client_sendq(expected, user, MSG);
	entry = get_channel_metadata(channel, "private/test", false);
	is_string("private/test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value2", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->read, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->write, MSG);
	is_int(METADATA_FLAG_EXCLUDE, entry->flags, MSG);

	standard_free();
}

static void metadata_set__member(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];
	char hostmask[USERHOST_REPLYLEN];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	snprintf(hostmask, sizeof(hostmask), "%s!%s@%s", user->name, user->username, user->host);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/test value1");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA NOT_ON_CHANNEL %s :You must be joined to the channel to set member metadata on it" CRLF, me.name, channel->chname);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	msptr = find_channel_membership(channel, user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/test value1");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s member/%s/test # :value1" CRLF, me.name, user->name, channel->chname, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_member_metadata(msptr, "test", false);
	ok(entry != NULL, MSG);
	is_string("test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value1", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_CHANNEL, entry->read, MSG);
	is_int(METADATA_ALLOW_SELF, entry->write, MSG);
	is_int(0, entry->flags, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/test :");
	snprintf(expected, sizeof(expected), ":%s 766 %s %s member/%s/test :Key not set" CRLF, me.name, user->name, channel->chname, user->name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/private/test value2");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION %s member/private/test :You do not have permission to set member/private/test on %s" CRLF, me.name, channel->chname, channel->chname);
	is_client_sendq(expected, user, MSG);
	is_hex(0, (uintptr_t)get_member_metadata(msptr, "private/test", false), MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/private/test value2");
	snprintf(expected, sizeof(expected), ":%s 761 %s %s member/%s/private/test o :value2" CRLF, me.name, user->name, channel->chname, user->name);
	is_client_sendq(expected, user, MSG);
	entry = get_member_metadata(msptr, "private/test", false);
	ok(entry != NULL, MSG);
	is_string("private/test", entry->key, MSG);
	is_string(hostmask, entry->setter, MSG);
	is_int(1, rb_dlink_list_length(&entry->values), MSG);
	is_string("value2", entry->values.head->data, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->read, MSG);
	is_int(METADATA_ALLOW_AUSPEX, entry->write, MSG);
	is_int(METADATA_FLAG_EXCLUDE, entry->flags, MSG);

	standard_free();
}

static void metadata_set__nopara(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * SET");
	is_client_sendq(":" TEST_ME_NAME " 461 " TEST_NICK " METADATA :Not enough parameters" CRLF, user, MSG);

	standard_free();
}

static void metadata_set__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * SET test value");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_set__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * SET test value");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_set__invalid_key(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * SET :");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY * :Invalid key" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SET :key with spaces");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY * :Invalid key" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SET INVALID value");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY INVALID :Invalid key" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SET member/test value");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY member/test :Member metadata may only be set on channels" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_CHANNEL " SET member/extra/slash value");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY member/extra/slash :Invalid key" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SET verylongkey" LONG_VALUE_100 " value");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_KEY verylongkey" LONG_VALUE_100 " :Invalid key" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_set__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA $ SET test value");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser SET test value");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan SET test value");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :No such channel" CRLF, user, MSG);

	standard_free();
}

static void metadata_set__invalid_value(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * SET test " LONG_VALUE_400);
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA INVALID_VALUE test :Value is too long" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_clear__user(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_user_metadata(user, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry->write = METADATA_ALLOW_SELF;
	entry = get_user_metadata(user, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry->write = METADATA_ALLOW_SELF;
	entry = get_user_metadata(user, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry->write = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(user, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	entry->write = METADATA_ALLOW_SERVICES;

	client_util_parse(user, "METADATA LChanPeon CLEAR");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION LChanPeon * :You do not have permission to clear keys on LChanPeon" CRLF, me.name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_NICK " CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test1 :Key not set" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test2 :Key not set" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	/* no warning for test3 because user can't read the key */
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA KEY_NO_PERMISSION %s test4 :You do not have permission to unset test4 on %s" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_NICK " CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test3 :Key not set" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA KEY_NO_PERMISSION %s test4 :You do not have permission to unset test4 on %s" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	entry = get_user_metadata(user, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry->write = METADATA_ALLOW_SELF;
	entry = get_user_metadata(user, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry->write = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA * CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test1 :Key not set" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test2 :Key not set" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA KEY_NO_PERMISSION %s test4 :You do not have permission to unset test4 on %s" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_clear__channel(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_channel_metadata(channel, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry->write = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry->write = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_OP;
	entry->write = METADATA_ALLOW_SERVICES;
	entry = get_channel_metadata(channel, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry->write = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA " TEST_CHANNEL " CLEAR");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA KEY_NO_PERMISSION %s * :You do not have permission to clear keys on %s" CRLF, me.name, channel->chname, channel->chname);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_CHANOP);
	client_util_parse(user, "METADATA " TEST_CHANNEL " CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test1 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test2 :Key not set" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA KEY_NO_PERMISSION %s test3 :You do not have permission to unset test3 on %s" CRLF, batch1, me.name, channel->chname, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	/* no warning for test4 because user can't read the key */
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s WARN METADATA KEY_NO_PERMISSION %s test3 :You do not have permission to unset test3 on %s" CRLF, batch2, me.name, channel->chname, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s test4 :Key not set" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_clear__large(void)
{
	char expected[BUFSIZE];
	char key[32];
	int refills = 0;

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	for (int i = 1; i <= 99; i++)
	{
		snprintf(key, sizeof(key), "test%02d", i);
		snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s %s :Key not set" CRLF, batch1, me.name, user->name, user->name, key);
		is_client_sendq_one(expected, user, MSG);

		if (rb_linebuf_len(&user->localClient->buf_sendq) == 0 && user->localClient->metadata_data != NULL)
		{
			rb_run_one_event_for_tests("metadata_iterate_clients");
			if (rb_linebuf_len(&user->localClient->buf_sendq) == 0)
			{
				ok(0, "metadata_iterate_clients failed; " MSG);
				return;
			}

			refills++;
		}
	}

	/* clear on a user clears member metadata too */
	for (int i = 1; i <= 99; i++)
	{
		snprintf(key, sizeof(key), "member/%s/test%02d", user->name, i);
		snprintf(expected, sizeof(expected), "@batch=%s :%s 766 %s %s %s :Key not set" CRLF, batch1, me.name, user->name, channel->chname, key);
		is_client_sendq_one(expected, user, MSG);

		if (rb_linebuf_len(&user->localClient->buf_sendq) == 0 && user->localClient->metadata_data != NULL)
		{
			rb_run_one_event_for_tests("metadata_iterate_clients");
			if (rb_linebuf_len(&user->localClient->buf_sendq) == 0)
			{
				ok(0, "metadata_iterate_clients failed; " MSG);
				return;
			}

			refills++;
		}
	}

	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);
	ok(refills > 0, MSG);

	standard_free();
}

static void metadata_clear__large_user_exit(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	/* this should trip ASAN (and probably cause a crash even on non-ASAN builds)
	 * if the client wasn't fully cleaned up */
	remove_local_person(user);
	rb_run_one_event_for_tests("free_exited_clients");
	rb_run_one_event_for_tests("metadata_iterate_clients");

	user = NULL;
	standard_free();
}

static void metadata_clear__large_channel_part(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	struct membership *msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;

	client_util_parse(user, "METADATA " TEST_CHANNEL " CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has LIST in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	remove_user_from_channel(msptr);
	rb_run_one_event_for_tests("metadata_iterate_clients");

	/* all channel metadata in init_large_metadata() is METADATA_ALLOW_CHANNEL for read perms,
	 * meaning leaving the channel denies access to all remaining keys; as such expect end of batch here */
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	ok(user->localClient->metadata_data == NULL, MSG);

	standard_free();
}

static void metadata_clear__abort(void)
{
	char expected[BUFSIZE];

	standard_init();
	init_large_metadata();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	struct membership *msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;

	client_util_parse(user, "METADATA * CLEAR");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);

	/* empty the sendq to make room for more messages.
	 * we're already testing the contents in a different test, so for this one just clear it */
	drain_client_sendq(user);

	/* verify the user still has CLEAR in progress */
	ok(user->localClient->metadata_data != NULL, MSG);

	/* sending a followup CLEAR aborts the first */
	client_util_parse(user, "METADATA " TEST_CHANNEL " CLEAR");
	snprintf(expected, sizeof(expected), "@batch=%s :%s FAIL METADATA ABORTED CLEAR :CLEAR aborted" CRLF, batch1, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);

	standard_free();
}

static void metadata_clear__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * CLEAR");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_clear__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * CLEAR");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_clear__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ CLEAR");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser CLEAR");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :No such nick" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan CLEAR");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :No such channel" CRLF, user, MSG);

	/* *ALL isn't special for CLEAR */
	client_util_parse(user, "METADATA *ALL CLEAR");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET *ALL :No such nick" CRLF, user, MSG);

	/* operspy clear doesn't exist because it makes no sense */
	make_local_person_auspex(user);
	client_util_parse(user, "METADATA !" TEST_NICK " CLEAR");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !" TEST_NICK " :No such nick" CRLF, user, MSG);

	standard_free();
}

static void metadata_sub(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH | CLICAP_LABELED_RESPONSE);

	client_util_parse(user, "@label=foo METADATA * SUB test1 test2 test3");
	snprintf(expected, sizeof(expected), "@label=foo :%s BATCH +%s labeled-response" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 770 %s test1 test2 test3" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 774 %s *ALL 0 :" SYNCLATER_AUTO CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_NICK " SUB test3 $test4 denied-test5 :test 6");
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY $test4 :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY denied-test5 :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY * :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s 770 %s test3" CRLF, me.name, user->name);
	is_client_sendq(expected, user, MSG);
	/* no new subs, so no RPL_METADATASYNCLATER */

	client_util_parse(user, "METADATA * SUB test4 test5 test6 test7 test8");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA LIMIT_REACHED test6 5 :Too many subscriptions" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s 770 %s test4 test5" CRLF, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s 774 %s *ALL 0 :" SYNCLATER_AUTO CRLF, me.name, user->name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SUB test3 test6 test1");
	snprintf(expected, sizeof(expected), ":%s FAIL METADATA LIMIT_REACHED test6 5 :Too many subscriptions" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s 770 %s test3" CRLF, me.name, user->name);
	is_client_sendq(expected, user, MSG);
	/* no new subs, so no RPL_METADATASYNCLATER */

	standard_free();
}

static void metadata_sub__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * SUB test1");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_sub__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * SUB test1");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_sub__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* non-self targets */
	client_util_parse(user, "METADATA " TEST_REMOTE2_NICK " SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_REMOTE2_NICK " :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_CHANNEL " :You may only target yourself" CRLF, user, MSG);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :You may only target yourself" CRLF, user, MSG);

	/* *ALL isn't special for SUB */
	client_util_parse(user, "METADATA *ALL SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET *ALL :You may only target yourself" CRLF, user, MSG);

	/* operspy sub doesn't exist because it makes no sense */
	make_local_person_auspex(user);
	client_util_parse(user, "METADATA !" TEST_NICK " SUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !" TEST_NICK " :You may only target yourself" CRLF, user, MSG);

	standard_free();
}

static void metadata_unsub(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * SUB test1 test2 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA " TEST_NICK " UNSUB test3 $test4 denied-test5 :test 6");
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY $test4 :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY denied-test5 :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s WARN METADATA INVALID_KEY * :Invalid key" CRLF, me.name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s 771 %s test3" CRLF, me.name, user->name);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA " TEST_NICK " UNSUB test1 test2 test3");
	snprintf(expected, sizeof(expected), ":%s 771 %s test1 test2 test3" CRLF, me.name, user->name);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_unsub__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_unsub__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_unsub__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* non-self targets */
	client_util_parse(user, "METADATA " TEST_REMOTE2_NICK " UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_REMOTE2_NICK " :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA " TEST_CHANNEL " UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_CHANNEL " :You may only target yourself" CRLF, user, MSG);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :You may only target yourself" CRLF, user, MSG);

	/* *ALL isn't special for UNSUB */
	client_util_parse(user, "METADATA *ALL UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET *ALL :You may only target yourself" CRLF, user, MSG);

	/* operspy unsub doesn't exist because it makes no sense */
	make_local_person_auspex(user);
	client_util_parse(user, "METADATA !" TEST_NICK " UNSUB test1");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !" TEST_NICK " :You may only target yourself" CRLF, user, MSG);

	standard_free();
}

static void metadata_subs(void)
{
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	client_util_parse(user, "METADATA * SUB test1 test1 test2 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA " TEST_NICK " SUBS");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata-subs" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 772 %s test1 test2 test3" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * UNSUB test2 test4");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA * SUBS");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata-subs" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 772 %s test1 test3" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_subs__nocap_batch(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA);

	client_util_parse(user, "METADATA * SUBS");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_subs__nocap_metadata(void)
{
	standard_init();
	SetClientCap(user, CLICAP_BATCH);

	client_util_parse(user, "METADATA * SUBS");
	is_client_sendq(":" TEST_ME_NAME " 421 " TEST_NICK " METADATA :Unknown command" CRLF, user, MSG);

	standard_free();
}

static void metadata_subs__invalid_target(void)
{
	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	/* non-self targets */
	client_util_parse(user, "METADATA " TEST_REMOTE2_NICK " SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_REMOTE2_NICK " :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET " TEST_CHANNEL " :You may only target yourself" CRLF, user, MSG);

	/* bogus targets that don't exist */
	client_util_parse(user, "METADATA $ SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET $ :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA NotAUser SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET NotAUser :You may only target yourself" CRLF, user, MSG);
	client_util_parse(user, "METADATA #NotAChan SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET #NotAChan :You may only target yourself" CRLF, user, MSG);

	/* *ALL isn't special for SUBS */
	client_util_parse(user, "METADATA *ALL SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET *ALL :You may only target yourself" CRLF, user, MSG);

	/* operspy subs doesn't exist because there's no legitimate need to list someone else's subscriptions */
	make_local_person_auspex(user);
	client_util_parse(user, "METADATA !" TEST_NICK " SUBS");
	is_client_sendq(":" TEST_ME_NAME " FAIL METADATA INVALID_TARGET !" TEST_NICK " :You may only target yourself" CRLF, user, MSG);

	standard_free();
}

static void metadata_sync__other(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	ClearInvisible(local_chan_p);

	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA * SUB test1 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_sync__other_invisible(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	SetInvisible(local_chan_p);

	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;

	client_util_parse(user, "METADATA * SUB test1 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_PEON);
	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch2);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA LChanPeon SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata LChanPeon" CRLF, me.name, batch3);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_sync__self(void)
{
	struct MetadataEntry *entry;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_user_metadata(user, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(user, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(user, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(user, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;

	client_util_parse(user, "METADATA * SUB test1 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA " TEST_NICK " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch1, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	client_util_parse(user, "METADATA * SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch2, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_NICK " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 o :value3" CRLF, batch3, me.name, user->name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

static void metadata_sync__channel(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);
	SetClientCap(local_chan_p, CLICAP_METADATA | CLICAP_BATCH);
	SetInvisible(local_chan_v);

	entry = get_channel_metadata(channel, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_channel_metadata(channel, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_channel_metadata(channel, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_v);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_user_metadata(local_chan_v, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_v, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_v, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_v, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;

	client_util_parse(user, "METADATA * SUB test1 test3");
	drain_client_sendq(user);
	client_util_parse(local_chan_p, "METADATA * SUB test2 test3 test4");
	drain_client_sendq(local_chan_p);

	/* for channel + member metadata, the channel metadata is listed first, then member in alphabetical order by nick */

	client_util_parse(user, "METADATA " TEST_CHANNEL " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch1, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	add_user_to_channel(channel, user, CHFL_VOICE);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch2, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch2, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test1 * :value1" CRLF, batch2, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch2);
	is_client_sendq(expected, user, MSG);

	msptr = find_channel_membership(channel, user);
	msptr->flags |= CHFL_CHANOP;
	client_util_parse(user, "METADATA " TEST_CHANNEL " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch3, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch3, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test1 * :value1" CRLF, batch3, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch3);
	is_client_sendq(expected, user, MSG);

	make_local_person_auspex(user);
	client_util_parse(user, "METADATA " TEST_CHANNEL " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch4, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test3 @ :value3" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 # :value1" CRLF, batch4, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test1 * :value1" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test3 o :value3" CRLF, batch4, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch4);
	is_client_sendq(expected, user, MSG);

	client_util_parse(local_chan_p, "METADATA " TEST_CHANNEL " SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata %s" CRLF, me.name, batch5, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s test2 # :value2" CRLF, batch5, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test2 # :value2" CRLF, batch5, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanPeon/test3 ! :value3" CRLF, batch5, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon LChanPeon test2 # :value2" CRLF, batch5, me.name);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon LChanPeon test4 ! :value4" CRLF, batch5, me.name);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon %s member/LChanVoice/test2 * :value2" CRLF, batch5, me.name, channel->chname);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 LChanPeon LChanVoice test2 # :value2" CRLF, batch5, me.name);
	is_client_sendq_one(expected, local_chan_p, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch5);
	is_client_sendq(expected, local_chan_p, MSG);

	standard_free();
}

static void metadata_sync__all(void)
{
	struct MetadataEntry *entry;
	struct membership *msptr;
	char expected[BUFSIZE];

	standard_init();
	add_user_to_channel(channel, user, CHFL_PEON);
	make_local_person_auspex(user);
	/* add monitors before adding caps to avoid automatic sync */
	client_util_parse(user, "MONITOR + LChanVoice,LNoChan");
	drain_client_sendq(user);
	SetClientCap(user, CLICAP_METADATA | CLICAP_BATCH);

	entry = get_channel_metadata(channel, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_channel_metadata(channel, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_channel_metadata(channel, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_OP;
	entry = get_channel_metadata(channel, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_p);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_member_metadata(msptr, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_member_metadata(msptr, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	msptr = find_channel_membership(channel, local_chan_v);
	entry = get_member_metadata(msptr, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_member_metadata(msptr, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_p, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_p, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_p, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_user_metadata(local_chan_v, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_chan_v, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_chan_v, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_chan_v, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_user_metadata(local_no_chan, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;
	entry = get_user_metadata(local_no_chan, "test2", true);
	set_metadata_value(entry, "test", "value2", false);
	entry->read = METADATA_ALLOW_CHANNEL;
	entry = get_user_metadata(local_no_chan, "test3", true);
	set_metadata_value(entry, "test", "value3", false);
	entry->read = METADATA_ALLOW_AUSPEX;
	entry = get_user_metadata(local_no_chan, "test4", true);
	set_metadata_value(entry, "test", "value4", false);
	entry->read = METADATA_ALLOW_SELF;
	entry = get_user_metadata(remote2_no_chan, "test1", true);
	set_metadata_value(entry, "test", "value1", false);
	entry->read = METADATA_ALLOW_ALL;

	client_util_parse(user, "METADATA * SUB test1 test3");
	drain_client_sendq(user);

	client_util_parse(user, "METADATA *ALL SYNC");
	snprintf(expected, sizeof(expected), ":%s BATCH +%s metadata *ALL" CRLF, me.name, batch1);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanPeon test3 o :value3" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanPeon/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LChanVoice test3 o :value3" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s %s member/LChanVoice/test1 * :value1" CRLF, batch1, me.name, user->name, channel->chname);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LNoChan test1 * :value1" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), "@batch=%s :%s 761 %s LNoChan test3 o :value3" CRLF, batch1, me.name, user->name);
	is_client_sendq_one(expected, user, MSG);
	snprintf(expected, sizeof(expected), ":%s BATCH -%s" CRLF, me.name, batch1);
	is_client_sendq(expected, user, MSG);

	standard_free();
}

int main(int argc, char *argv[])
{
	plan_lazy();

	ircd_util_init(__FILE__);
	client_util_init();

	srand(0);
	generate_batch_id(batch1, sizeof(batch1));
	generate_batch_id(batch2, sizeof(batch2));
	generate_batch_id(batch3, sizeof(batch3));
	generate_batch_id(batch4, sizeof(batch4));
	generate_batch_id(batch5, sizeof(batch5));
	generate_batch_id(batch6, sizeof(batch6));
	generate_batch_id(batch7, sizeof(batch7));
	generate_batch_id(batch8, sizeof(batch8));

	CLICAP_METADATA = capability_get(cli_capindex, "draft/metadata-3", NULL);
	ok(CLICAP_METADATA != 0, "CLICAP_METADATA missing; " MSG);

	metadata_key_usage_tracking();
	metadata_sub_tracking();

	set_metadata_value__new();
	set_metadata_value__append();

	metadata_get__other();
	metadata_get__self();
	metadata_get__channel();
	metadata_get__member();
	metadata_get__nopara();
	metadata_get__nocap_batch();
	metadata_get__nocap_metadata();
	metadata_get__invalid_key();
	metadata_get__invalid_target();

	metadata_list__channel();
	metadata_list__other();
	metadata_list__other_invisible();
	metadata_list__self();
	metadata_list__large();
	metadata_list__large_user_exit();
	metadata_list__large_target_exit();
	metadata_list__large_channel_part();
	metadata_list__large_channel_destroy();
	metadata_list__large_abort();
	metadata_list__nocap_batch();
	metadata_list__nocap_metadata();
	metadata_list__invalid_target();

	metadata_set__self();
	metadata_set__channel();
	metadata_set__member();
	metadata_set__nopara();
	metadata_set__nocap_batch();
	metadata_set__nocap_metadata();
	metadata_set__invalid_key();
	metadata_set__invalid_target();
	metadata_set__invalid_value();

	metadata_clear__user();
	metadata_clear__channel();
	metadata_clear__large();
	metadata_clear__large_user_exit();
	metadata_clear__large_channel_part();
	metadata_clear__abort();
	metadata_clear__nocap_batch();
	metadata_clear__nocap_metadata();
	metadata_clear__invalid_target();

	metadata_sub();
	metadata_sub__nocap_batch();
	metadata_sub__nocap_metadata();
	metadata_sub__invalid_target();

	metadata_unsub();
	metadata_unsub__nocap_batch();
	metadata_unsub__nocap_metadata();
	metadata_unsub__invalid_target();

	metadata_subs();
	metadata_subs__nocap_batch();
	metadata_subs__nocap_metadata();
	metadata_subs__invalid_target();

	metadata_sync__self();
	metadata_sync__other();
	metadata_sync__other_invisible();
	metadata_sync__channel();
	metadata_sync__all();

	client_util_free();
	ircd_util_free();
	return 0;
}
