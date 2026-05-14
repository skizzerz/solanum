# METADATA documentation

The solanum metadata system provides a flexible way for clients, services, and
modules to associate arbitrary data with users, channels, or the membership of
a user in a channel.

The client-facing `METADATA` command is implemented as specified by the
[IRCv3 metadata-2 specification](https://ircv3.net/specs/extensions/metadata).
Solanum implements a handful of nonstandard extensions to the specification,
as described below.

## Namespaces

A key may belong to a namespace (a prefix followed by `/`) to give the key
special handling by default. There are three recognized namespaces: services,
private, and member. Any other prefix is not treated specially. Keys belonging
to one of the special namespaces have different permissions when the keys are
not registered in advance by a module or an external server.

Keys in the services namespace (`services/*`) are readable only by opers with
the `auspex:metadata` privilege and are only writable by services. Keys in the
private namespace (`private/*`) are readable and writable only by opers with
the `auspex:metadata` privilege.

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
to keys in this namespace should omit the nick portion, and will cause a
subscription to all members of joined channels with that key defined.
Subscription notification messages *will* include the nickname portion.

If a key is not in one of the above special namespaces, user metadata keys
are visible to everyone and writable only by that user while channel metadata
keys are visible to channel members and writable only by channel operators.

## Client interface

### draft/metadata-2 capability

Clients must negotiate both the draft/metadata-2 capability as well as the
batch capability in order to use the `METADATA` command. Attempts to use the
command without both capabilities will result in the command being rejected
with the ERR_UNKNOWNCOMMAND (421) numeric.

The capability is published with the following tokens:

- max-subs: Indicates the maximum number of subscriptions a user can have.
- max-keys: Indicates the maximum number of metadata keys a user can set
  on themselves or a channel. Membership keys count against that user's limit.
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

### METADATA GET

This command works as described in the specification. Custom keys may appear
multiple times in the response batch with different values, indicating a value
that is broken up because it is too long for a single IRC line or a "list" of
values. Standard keys (as defined in the IRCv3 registry) will never have this
behavior and will only appear at most once in the response batch.

### METADATA LIST

This command works as described in the specification, with the same note
regarding long or list-type values for custom keys as `METADATA GET`. If the
client lacks permission to view certain keys, they will be omitted entirely
from the response. `FAIL METADATA KEY_NO_PERMISSION` will never be sent as a
result of this command, but the batch may have no contents if the user cannot
see any keys associated with the target.

### METADATA SET

This command works as described in the specification. The member namespace
works as described above when setting it on a channel target. A member
namespace prefix is not treated specially if set on a user target.

### METADATA CLEAR

This command works as described in the specification. When run on a channel,
member keys are *not* cleared. When run on a user, member keys for that user
*are* cleared. This is because those keys count against the user's metadata
limits rather than the channel's. Keys which the user does not have permission
to write will be ignored when clearing the keys.
`FAIL METADATA KEY_NO_PERMISSION` will never be sent on a per-key basis as a
result of this command, but may be sent with the `*` key if the user does not
have permission to clear keys on the target in general.

Opers with `auspex:metadata` may clear keys on any target. Otherwise, a user
may only clear their own user keys or channel keys on channels they are an
operator on.

### METADATA SUB

This command works as described in the specification. Clients will never
receive `FAIL METADATA KEY_NO_PERMISSION` for any subscriptions as permissions
are not checked during this command, only when keys would be broadcast. They
will simply never receive those keys until they attain appropriate permissions.

This command will not cause any metadata notifications to be sent to the
client; it must manually request the updated list via `METADATA SYNC` after it
has finished sending all relevant `METADATA SUB` commands.

### METADATA UNSUB

This command works as described in the specification.

### METADATA SUBS

This command works as described in the specification. The output is delivered
potentially asynchronously if it is too large and would otherwise flood the
client off of the network. Issuing `METADATA SUBS` while an asynchronous
metadata operation is already in progress will abort the previous operation
prematurely.

### METADATA SYNC

This command works as described in the specification. The output is delivered
potentially asynchronously if it is too large and would otherwise flood the
client off of the network. Issuing `METADATA SYNC` while an asynchronous
metadata operation is already in progress will abort the previous operation
prematurely. Solanum ratelimits `METADATA SYNC` and will reply with
`RPL_METADATASYNCLATER` if the client requests metadata too frequently.

### JOIN

When joining a channel, solanum will always respond with
`RPL_METADATASYNCLATER`. The client should send a single `METADATA SYNC` after
joining all channels to synchronize the metadata list.

### MONITOR

Solanum does not support metadata notifications for monitored targets. Because
solanum does not support `METADATA` before user registration has completed,
there is no possiblity for a newly online user to have any metadata set on
them.

Adding a target who is already online to the monitor list will cause solanum
to send `RPL_METADATASYNCLATER`, indicating a manual `METADATA SYNC` must be
run in order to retrieve the metadata list for that user. This should be
performed by the client once after adding all nicknames to the monitor list.

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
metadata-related settings. See reference.conf for more details.

### 
