# Phase 1 - Baseline Chat Application
 
## Protocol Description
 
### Message Framing
 
Every message exchanged between a client and the server is a length-prefixed frame:
 
```
[4 bytes: payload length, network byte order] [payload bytes]
```
 
The 4-byte header is written using `htonl()` on the sending side and decoded with
`ntohl()` on the receiving side, so both sides agree on the byte order regardless
of the underlying machine's architecture.
 
The payload itself is a pipe-delimited text command:
 
```
TYPE|field1|field2
```
 
Examples:
- `REGISTER|alice`
- `MSG|bob|hello there`
- `WHO|`
- `WHO_RESP|bob,alice`
- `QUIT|`
The content field (when present) is always last, so it may safely contain `|`
characters without breaking the parser, since the parser only splits on the
first two `|` delimiters.
 
### Determining When a Message is Complete
 
TCP is a byte stream, not a message stream - it makes no guarantee that one
`send()` call on one side corresponds to one `recv()` call on the other. Two
messages sent back-to-back can arrive concatenated in a single `recv()`; a
large message can be split across several `recv()` calls.
 
Our protocol solves this with the length-prefix header described above. The
receiver:
 
1. Reads exactly 4 bytes (looping over `recv()` as many times as needed to get
   all 4, since a single `recv()` call is not guaranteed to return everything
   requested).
2. Decodes those 4 bytes as the payload length.
3. Reads exactly that many more bytes to obtain the complete payload.
Because the receiver never asks `recv()` for more bytes than it currently
needs, it can never accidentally consume bytes belonging to the next message,
regardless of how the OS happened to batch or split the underlying TCP
segments.
 
### Routing With More Than Two Clients
 
The server maintains client state in an `unordered_map<std::string, int>`
mapping each registered username to its socket file descriptor, protected by
a `std::mutex` for safe concurrent access from each client's handler thread.
 
This design is not limited to two participants. Routing a message simply
looks up the destination username in the map and forwards to the
corresponding socket, so any number of simultaneously connected clients are
handled identically - a third client connecting and registering would become
an equally valid message destination with no code changes required.
 
---
 
## Challenges Faced
 
### 1. Stray newline breaking username lookups
 
When reading the registration message from a client, a trailing newline
character was ending up stored as part of the username string in the
`unordered_map`. This meant that later lookups via `clients.find(username)` -
using a username parsed from a different message that did not have the
trailing newline - failed to match, even though the two strings looked
identical when printed. This was fixed by introducing a `trim()` helper that
strips leading and trailing whitespace from every string extracted from raw
network input before it is used as a map key or compared.
 
### 2. `recv()` cannot determine message boundaries on its own
 
`recv()` returns whatever bytes happen to be available in the kernel's
receive buffer at the time it is called - it has no concept of "one message."
Two messages sent back-to-back could arrive concatenated in a single
`recv()` call, or a single message could be split across multiple `recv()`
calls, even though the bytes always arrive in order. This was fixed by
introducing a 4-byte length prefix before every message: the sender writes
how many bytes the payload contains, and the receiver reads exactly that many
bytes for the payload, regardless of how many underlying `recv()` calls it
takes.
 
### 3. Residual race condition on concurrent sends to the same socket
 
Even after adding length-prefixed framing, a race condition remained: the
framing header and payload were originally written as two separate `send()`
calls. If two different threads (e.g., two senders both messaging the same
recipient) called `send()` on the *same* target socket at close to the same
time, their header and payload writes could interleave on the wire - for
example, one thread's length header could be immediately followed by
another thread's length header, before either thread's actual payload went
out. This desynchronizes the receiver, since it consumes bytes assuming a
fixed header-then-payload structure, and a later frame can end up
misinterpreting stray payload bytes as a new (garbage) length value.

The fix was to give every socket its own dedicated `std::mutex`, held for the
entire header-plus-payload send, so that two threads writing to the same
socket are always serialized with respect to each other rather than
interleaving mid-frame.
