# Phase 3 - Server Authentication via PKI

Adds a minimal PKI on top of Phase 2: a self-signed Certificate Authority,
a CA-signed server certificate, client-side certificate validation, and a
challenge-response proof-of-possession mechanism - all performed before any
Diffie-Hellman activity. Also includes an updated MITM proxy demonstrating
that the Phase 2 attack now fails.

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
./mitm_proxy <listen_port> <real_server_ip> <real_server_port> <mallory_cert_path> <mallory_key_path>
```