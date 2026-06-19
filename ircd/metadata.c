/*
 * Solanum: a slightly advanced ircd
 * metadata.c: Utilities to read and manipulate metadata entries on users and channels
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
#include "metadata.h"
#include "s_assert.h"

/* in addition to statistics tracking via the value, the dictionary keys hold a unique
 * copy of each metadata key, allowing struct MetadataEntry to reference this copy
 * for deduplication instead of allocating N copies of each key */
rb_dictionary *metadata_key_usage = NULL;

void
init_metadata(void)
{
	metadata_key_usage = rb_dictionary_create("metadata keys", rb_strcmp);
}

static const char *
incr_key(const char *key)
{
	rb_dictionary_element *elem = rb_dictionary_find(metadata_key_usage, key);

	if (elem == NULL)
	{
		char *dup = rb_strdup(key);
		rb_dictionary_add(metadata_key_usage, dup, (void *)1);
		return dup;
	}

	uintptr_t val = (uintptr_t)elem->data;
	val++;
	elem->data = (void *)val;
	return elem->key;
}

static void
decr_key(const char *key)
{
	rb_dictionary_element *elem = rb_dictionary_find(metadata_key_usage, key);
	if (elem == NULL)
		return;

	uintptr_t val = (uintptr_t)elem->data;
	val--;

	if (val == 0)
	{
		char *dup = (char *)elem->key;
		rb_dictionary_delete(metadata_key_usage, key);
		rb_free(dup);
	}
	else
		elem->data = (void *)val;
}

struct MetadataEntry *
get_user_metadata(struct Client *target_p, const char *key, bool create)
{
	struct MetadataEntry *metadata = NULL;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, target_p->metadata.head)
	{
		struct MetadataEntry *data = ptr->data;
		int res = strcmp(key, data->key);
		if (res == 0)
		{
			metadata = data;
			break;
		}

		if (res < 0)
			break;
	}

	if (metadata == NULL && create)
	{
		metadata = rb_malloc(sizeof(struct MetadataEntry));
		metadata->type = METADATA_USER;
		metadata->key = incr_key(key);
		metadata->target_p = target_p;
		metadata->read = METADATA_ALLOW_SERVICES;
		metadata->write = METADATA_ALLOW_SERVICES;
		metadata->node = rb_make_rb_dlink_node();
		metadata->flags = METADATA_FLAG_NEW;
		if (ptr == NULL)
			rb_dlinkAddTail(metadata, metadata->node, &target_p->metadata);
		else
			rb_dlinkAddBefore(ptr, metadata, metadata->node, &target_p->metadata);
	}

	return metadata;
}

struct MetadataEntry *
get_channel_metadata(struct Channel *chptr, const char *key, bool create)
{
	struct MetadataEntry *metadata = NULL;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, chptr->metadata.head)
	{
		struct MetadataEntry *data = ptr->data;
		int res = strcmp(key, data->key);
		if (res == 0)
		{
			metadata = data;
			break;
		}

		if (res < 0)
			break;
	}

	if (metadata == NULL && create)
	{
		metadata = rb_malloc(sizeof(struct MetadataEntry));
		metadata->type = METADATA_CHANNEL;
		metadata->key = incr_key(key);
		metadata->chptr = chptr;
		metadata->read = METADATA_ALLOW_SERVICES;
		metadata->write = METADATA_ALLOW_SERVICES;
		metadata->node = rb_make_rb_dlink_node();
		metadata->flags = METADATA_FLAG_NEW;
		if (ptr == NULL)
			rb_dlinkAddTail(metadata, metadata->node, &chptr->metadata);
		else
			rb_dlinkAddBefore(ptr, metadata, metadata->node, &chptr->metadata);
	}

	return metadata;
}

struct MetadataEntry *
get_member_metadata(struct membership *msptr, const char *key, bool create)
{
	struct MetadataEntry *metadata = NULL;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, msptr->metadata.head)
	{
		struct MetadataEntry *data = ptr->data;
		int res = strcmp(key, data->key);
		if (res == 0)
		{
			metadata = data;
			break;
		}

		if (res < 0)
			break;
	}

	if (metadata == NULL && create)
	{
		metadata = rb_malloc(sizeof(struct MetadataEntry));
		metadata->type = METADATA_MEMBER;
		metadata->key = incr_key(key);
		metadata->msptr = msptr;
		metadata->read = METADATA_ALLOW_SERVICES;
		metadata->write = METADATA_ALLOW_SERVICES;
		metadata->node = rb_make_rb_dlink_node();
		metadata->flags = METADATA_FLAG_NEW;
		if (ptr == NULL)
			rb_dlinkAddTail(metadata, metadata->node, &msptr->metadata);
		else
			rb_dlinkAddBefore(ptr, metadata, metadata->node, &msptr->metadata);
	}

	return metadata;
}

void
set_metadata_value(struct MetadataEntry *metadata, const char *setter, const char *value, bool append)
{
	rb_dlink_node *ptr, *nptr;

	if (!append)
	{
		RB_DLINK_FOREACH_SAFE(ptr, nptr, metadata->values.head)
		{
			rb_free(ptr->data);
			rb_dlinkDestroy(ptr, &metadata->values);
		}

		rb_free(metadata->setter);
		metadata->setter = setter == NULL ? rb_strdup(me.name) : rb_strdup(setter);
	}

	rb_dlinkAddTailAlloc(rb_strdup(value), &metadata->values);
	metadata->flags &= ~(METADATA_FLAG_NEW | METADATA_FLAG_DELETED | METADATA_FLAG_MARKED);
}

static void
free_metadata_list(rb_dlink_list *list)
{
	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH_SAFE(ptr, nptr, list->head)
	{
		free_metadata(ptr->data);
	}
}

void
free_client_metadata(struct Client *target_p)
{
	free_metadata_list(&target_p->metadata);
}

void
free_channel_metadata(struct Channel *chptr)
{
	free_metadata_list(&chptr->metadata);
}

void
free_member_metadata(struct membership *msptr)
{
	free_metadata_list(&msptr->metadata);
}

void
free_metadata(struct MetadataEntry *entry)
{
	rb_dlink_node *ptr, *nptr;
	if (entry == NULL)
		return;

	switch (entry->type)
	{
	case METADATA_USER:
		rb_dlinkDestroy(entry->node, &entry->target_p->metadata);
		break;
	case METADATA_CHANNEL:
		rb_dlinkDestroy(entry->node, &entry->chptr->metadata);
		break;
	case METADATA_MEMBER:
		rb_dlinkDestroy(entry->node, &entry->msptr->metadata);
		break;
	default:
		/* memory corruption (double free?) */
		s_assert(0);
	}

	decr_key(entry->key);
	RB_DLINK_FOREACH_SAFE(ptr, nptr, entry->values.head)
	{
		rb_free(ptr->data);
		rb_dlinkDestroy(ptr, &entry->values);
	}

	rb_free(entry->setter);
	rb_free(entry);
}
