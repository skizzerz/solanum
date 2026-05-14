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

#include <stdbool.h>

struct Channel;
struct Client;
struct membership;

/*
 * Used for modules or external services to denote keys that require special privileges to read/write.
 * Keys do not need to be registered before they can be set or subscribed to.
 * Returns true if the key wasn't previously registered or the permissions match the previous registration.
 * See doc/features/metadata.md for more information on how solanum implements metadata support.
 */
bool register_user_metadata_key(const char *key, const char *read_perm, const char *write_perm);
bool register_channel_metadata_key(const char *key, const char *read_perm, const char *write_perm);
bool register_member_metadata_key(const char *key, const char *read_perm, const char *write_perm);

const char *get_user_metadata(struct Client *source_p, struct Client *target_p, const char *key);
const char *get_channel_metadata(struct Channel *source_p, struct Channel *chptr, const char *key);
const char *get_member_metadata(struct Channel *source_p, struct membership *msptr, const char *key);
int set_user_metadata(struct Client *source_p, struct Client *target_p, const char *key, const char *value);
int set_channel_metadata(struct Channel *source_p, struct Channel *target_p, const char *key, const char *value);
int set_member_metadata(struct Channel *source_p, struct membership *msptr, const char *key, const char *value);

#endif /* INCLUDED_metadata_h */
