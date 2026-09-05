# Phase 4 - End-to-End Encryption Between Clients

Adds a second, independent layer of encryption directly between two
clients, established via the `/e2e username` command. The client-to-client
key exchange is tunneled through the existing encrypted client-server link
using the `__E2E_INIT__`/`__E2E_ACK__`/`__E2E_MSG__` wire tags, so the
server relays it without ever being able to derive the resulting key or
read chat content once a session is established.

## Build

```bash
./setup_ca.sh
make
```

`libssl-dev` must be installed (`sudo apt install -y libssl-dev`).

## Run

```bash
./server <port>
./client <server_ip> <port> <username>
```

Once connected, use `/e2e <username>` to establish an end-to-end session
with another client before chatting.