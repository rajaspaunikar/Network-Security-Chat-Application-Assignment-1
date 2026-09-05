# Phase 5 - Forward Secrecy

Extends the Phase 4 end-to-end session so the client-to-client key is
automatically renegotiated every 60 seconds for as long as the session
stays active, using generation-tagged keys and a deterministic
(lexicographic) tie-break to avoid both clients initiating a rotation
simultaneously.

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

Once connected, use `/e2e <username>` to establish an end-to-end session -
the key will automatically rotate every 60 seconds thereafter.