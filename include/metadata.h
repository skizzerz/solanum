/*
 * Solanum: a slightly advanced ircd
 * metadata.h: Utilities to read and manipulate metadata entries on users and channels
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

#ifndef INCLUDED_metadata_h
#define INCLUDED_metadata_h

#include "stdinc.h"

/* Metadata key deleted by a client */
#define METADATA_FLAG_DELETED 0x01
/* Marks the key to be freed during next purge run */
#define METADATA_FLAG_MARKED  0x02
/* The MetadataEntry was created due to passing create=true to get_*_metadata
 * This flag gets cleared after set_metadata_value is called */
#define METADATA_FLAG_NEW     0x04
/* Marks that the key should not be counted against the target's metadata limits */
#define METADATA_FLAG_EXCLUDE 0x08

struct Channel;
struct Client;
struct membership;

enum metadata_type
{
	METADATA_USER,
	METADATA_CHANNEL,
	METADATA_MEMBER
};

enum metadata_perm
{
	METADATA_ALLOW_ALL,
	METADATA_ALLOW_CHANNEL,
	METADATA_ALLOW_OP,
	METADATA_ALLOW_OVERRIDE,
	METADATA_ALLOW_SELF,
	METADATA_ALLOW_AUSPEX,
	METADATA_ALLOW_SERVICES,
};

struct MetadataEntry
{
	enum metadata_type type;
	const char *key;
	char *setter;
	time_t tsinfo;
	union
	{
		struct Client *target_p;
		struct Channel *chptr;
		struct membership *msptr;
	};
	rb_dlink_list values;
	enum metadata_perm read;
	enum metadata_perm write;
	rb_dlink_node *node;
	uint32_t flags;
};

/* dictionary of key name to number of metadata entries using the key, for statistics tracking */
extern rb_dictionary *metadata_key_usage;

void init_metadata(void);
struct MetadataEntry *get_user_metadata(struct Client *target_p, const char *key, bool create);
struct MetadataEntry *get_channel_metadata(struct Channel *chptr, const char *key, bool create);
struct MetadataEntry *get_member_metadata(struct membership *msptr, const char *key, bool create);
void set_metadata_value(struct MetadataEntry *metadata, const char *setter, const char *value, bool append);
void free_client_metadata(struct Client *target_p);
void free_channel_metadata(struct Channel *chptr);
void free_member_metadata(struct membership *msptr);
void free_metadata(struct MetadataEntry *entry);

#endif /* INCLUDED_metadata_h */
