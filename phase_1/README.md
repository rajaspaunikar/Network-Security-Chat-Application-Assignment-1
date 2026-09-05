# Phase 1 - Baseline Chat Application

A one-to-one TCP chat application with no security - server and clients
exchange messages in plaintext. Supports one server and two clients
connected simultaneously, with the `@username`, `/chat`, `/who`, and
`/quit` command interface.

## Build

```bash
g++ -std=c++17 -Wall -pthread server.cpp -o server
g++ -std=c++17 -Wall -pthread client.cpp -o client
```

## Run

```bash
./server <port>
./client <server_ip> <port> <username>
```