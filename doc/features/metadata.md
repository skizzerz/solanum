# METADATA documentation

The solanum metadata system provides a flexible way for clients, services, and
modules to associate arbitrary data with users, channels, or the membership of
a user in a channel.

The client-facing `METADATA` command is implemented as specified by the
[IRCv3 metadata specification](https://ircv3.net/specs/extensions/metadata).
Solanum implements a handful of nonstandard extensions to the specification,
as described below.

## Namespaces

A key may belong to a namespace (a prefix followed by `/`) to give the key
special handling by default. There are three recognized namespaces: services,
private, and member. Any other prefix is not treated specially. Keys belonging
to one of the special namespaces have different permissions than normal.

Keys in the services namespace (`services/*`) are readable only by opers with
the `auspex:metadata` privilege and are only writable by services. Keys in the
private namespace (`private/*`) are readable and writable only by opers with
the `auspex:metadata` privilege. Keys in either of these namespaces do not
count against the target's metadata key limit.

The member namespace implements key name remapping in order to associate
metadata with a specific user in a specific channel. These keys may also be
annotated with services or private (e.g. `member/services/privs`) to adjust
default read and write privileges but may otherwise not contain any additional
slashes in their name. If no special privileges are given to these keys, they
are readable by all members of the channel and writable only by the member
they are associated with. When viewing such keys, the name will be exposed to
clients as `member/<nick>/<name>` instead (where nick is the member associated
with the metadata entry and name is the remainder of the key name). The
special member namespace is only available via the client-to-server `METADATA`
command. Server-to-server metadata commands can directly view and set member
metadata without needing to re-map it through channel metadata. Subscriptions
to keys in this namespace should omit the member prefix and nick portion, and
will cause a subscription to all members of joined channels with that key
defined. Subscription notification messages *will* include the nickname
portion. For example, subscribing to `display-name` will also produce
notifications for `member/<nick>/display-name` in shared channels.

When setting member keys, they must be set on a channel and must omit the nick
portion. For example, `METADATA #channel SET member/display-name` will set the
user's `display-name` on their membership in `#channel`. Numeric responses to
this command (`RPL_KEYVALUE`/`RPL_KEYNOTSET`) *will* include the nick portion,
but error responses (e.g. `FAIL METADATA KEY_NO_PERMISSION`) will not.

If a key is not in one of the above special namespaces, user metadata keys
are visible to everyone and writable only by that user while channel metadata
keys are visible to channel members and writable only by channel operators.
This can be further adjusted by configuration (e.g. the default configuration
allows for the avatar and display-name channel metadata keys to be visible to
everyone).

## Visibility

The following symbols can appear as the "visibility" of a metadata key:

- `*` indicates the key is readable by everyone
- `#` indicates the key is readable by channel members (for channel/member
  metadata) or by users in shared channels (for user metadata)
- `@` indicates the key is readable by channel operators (only valid for
  channel metadata)
- `!` indicates the key is readable only by the user the entry is associated
  with (only valid for user/member metadata)
- `o` indicates the key is readable by opers with the `metadata:auspex` priv

Regardless of the key's stated visibility, the following additional
restrictions apply when reading metadata:

- On a `+p` or `+s` channel the user is not a member of, `METADATA LIST` and
  `METADATA SYNC` will not list member namespace metadata for that channel.
  Additionally, if `METADATA SYNC` is run on such a channel, it will not list
  metadata for that channel's users.
- On a `+i` user target, `METADATA LIST` and `METADATA SYNC` will not list
  member namespace metadata for channels the user and target don't share.

## Client interface

### draft/metadata-3 capability

Clients must negotiate both the draft/metadata-3 capability as well as the
batch capability in order to use the `METADATA` command. Attempts to use the
command without both capabilities will result in the command being rejected
with the `ERR_UNKNOWNCOMMAND` (421) numeric.

The capability is published with the following tokens:

- max-subs: Indicates the maximum number of subscriptions a user can have.
- max-keys: Indicates the maximum number of metadata keys a user can set
  on themselves or a channel. Membership keys count against that user's limit.
  Keys in the private and services namespaces do not count against this limit.
- max-key-bytes: Indicates the maximum size of a single key. Keys sent by the
  server may exceed this limit; it is only enforced for METADATA SET commands
  issued by clients.
- max-value-bytes: Indicates the maximum size of a value for a single key.
  Values sent by the server may exceed this limit; it is only enforced for
  METADATA SET commands issued by clients.
- solanum.chat/member: Indicates support for the special member namespace.
  This token has no value.

Solanum does not support the `METADATA` command before user registration has
completed, and as such does not advertise the before-connect token.

Turning either this capability or the batch capability off will clear the
client's metadata subscription list and abort any in-progress asynchronous
metadata notifications.

### Notifications

`METADATA` notifications will be sent per the specification when keys change
or are deleted. If a key is deleted, the notification will have an empty
(but not omitted) value parameter.

### METADATA ABORT

This command is a solanum-specific extension to the specification.

This command aborts an in-progress asynchronous metadata operation (`LIST`,
`SYNC`, or `CLEAR`). If no such operations are in progress, it will return
`NOTE METADATA NO_ASYNC_OP`. Sending a second `LIST` or `CLEAR` command while
one is already in progress will similarly abort the previous command. Sending
a `SYNC` while another `SYNC` is in progress will return
`RPL_METADATASYNCLATER` but will abort any in-progress non-`SYNC` operations.

### METADATA GET

This command works as described in the specification. Custom keys may appear
multiple times in the response batch with different values, indicating a value
that is broken up because it is too long for a single IRC line or a "list" of
values.

### METADATA LIST

This command works as described in the specification, with the same note
regarding long or list-type values for custom keys as `METADATA GET`. If the
client lacks permission to view certain keys, they will be omitted entirely
from the response. `WARN METADATA KEY_NO_PERMISSION` will never be sent as a
result of this command, but the batch may have no contents if the user cannot
see any keys associated with the target.

This command is processed asynchronously and will never result in the client
being disconnected due to exceeding their SendQ limit.

This command is rate-limited.

### METADATA SET

This command works as described in the specification. The member namespace
works as described above when setting it on a channel target. A member
namespace prefix is invalid if set on a user target.

This command is rate-limited.

### METADATA CLEAR

This command works as described in the specification. When run on a channel,
member keys are *not* cleared. When run on a user, member keys for that user
*are* cleared. This is because those keys count against the user's metadata
limits rather than the channel's. Keys which the user does not have permission
to write will be ignored when clearing the keys; however,
`WARN METADATA KEY_NO_PERMISSION` will be sent for such keys as long as the
user is able to read that key.

This command is rate-limited.

### METADATA SUB

This command works as described in the specification. Clients will never
receive `NOTE METADATA KEY_NO_PERMISSION` for any subscriptions as permissions
are not checked during this command, only when keys would be broadcast. They
will simply never receive those keys until they attain appropriate permissions.

This command will not cause any metadata notifications to be sent to the
client; it must manually request the updated list via `METADATA *ALL SYNC`
after it has finished sending all relevant `METADATA SUB` commands.

### METADATA UNSUB

This command works as described in the specification.

### METADATA SUBS

This command works as described in the specification.

### METADATA SYNC

This command works as described in the specification. The output is delivered
potentially asynchronously if it is too large and would otherwise flood the
client off of the network. Issuing `METADATA SYNC` while an asynchronous
metadata operation is already in progress will abort the previous operation
prematurely. Solanum ratelimits `METADATA SYNC` and will reply with
`RPL_METADATASYNCLATER` if the client requests metadata too frequently.

This command is processed asynchronously and will never result in the client
being disconnected due to exceeding their SendQ limit.

### JOIN

When joining a channel, solanum will always respond with
`RPL_METADATASYNCLATER`. The client should send a single `METADATA *ALL SYNC`
after joining all channels to synchronize the metadata list, rather than
running a per-channel `SYNC`.

### MONITOR

Adding a target who is already online to the monitor list will cause solanum
to send `RPL_METADATASYNCLATER`, indicating a manual `METADATA *ALL SYNC` must
be run in order to retrieve the metadata list for that user. This should be
performed by the client once after adding all nicknames to the monitor list,
rather than performing a per-nickname `SYNC`.

### WHOIS

The metadata returned in a `WHOIS` command is dependent on network
configuration. By default, the following user metadata keys are exposed in
`WHOIS`:

- display-name
- pronouns
- status

## Server interface

### Configuration

A new top-level configuration block named metadata allows for configuration of
metadata-related settings. See `reference.conf` for more details.

### Commands

Four server-to-server commands have been added to allow metadata propagation:

- `ENCAP MDA` to append new data to existing metadata keys
- `ENCAP MDD` to delete metadata keys
- `ENCAP MDI` to adjust metadata key information (permissions, setter, flags)
- `ENCAP MDS` to create or overwrite metadata keys

Please see `doc/technical/ts6.md` for more details on these commands.

## API

Solanum core provides a minimal API for retrieving and setting metadata. This
API does not concern itself with permissions checks and does not require that
the metadata module be loaded. Without the module, server-to-server metadata
is not supported, so the usefulness of this API is very limited in such cases.

The three functions `get_user_metadata`, `get_channel_metadata`, and
`get_member_metadata` can retrieve and optionally create a new metadata entry
for a specified key if it doesn't already exist. If creation is not requested,
they will return `NULL` if the key does not exist. Newly created entries have
no end-user permissions to read or write to them; the caller should set
permissions appropriately as well as timestamp information (generally, this
is taken care of via the m_metadata module, but other modules that set
internal metadata will need to do this themselves).

The `set_metadata_value` function is used to write a value to the metadata
entry. Prefer using this function over writing to the `values` list directly,
as this function will save typing by automatically clearing out the old value.
An optional "append" mode is provided to support multiple values for a single
metadata key.

Finally, the `free_metadata` function is used to delete a metadata entry and
release all of its memory. This function will additionally clear it from all
appropriate tracking variables.

The m_metadata module provides hooks for additional metadata management:

- `can_metadata`: This hook is used to determine if a user has permission to
  read or write to a specific metadata key.
- `metadata_permissions`: This hook is used to adjust the permissions of
  newly created metadata keys.
- `set_metadata`: This hook allows for filtering or modifying metadata values
  before they are set.

See `doc/technical/hooks.md` for more information on using these hooks.
