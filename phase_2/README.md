# Phase 2 - Client-Server Confidentiality via Diffie-Hellman

Adds a from-scratch Diffie-Hellman key exchange (RFC 3526 Group 14) between
each client and the server, with all subsequent traffic - including
registration - encrypted using AES-256-GCM. Also includes a standalone
man-in-the-middle proxy demonstrating that DH alone provides no
authentication.

## Build

```bash
g++ -std=c++17 -Wall dh.cpp test_dh.cpp -o test_dh -lcrypto

g++ -std=c++17 -Wall -pthread crypto.cpp dh.cpp server.cpp -o server -lcrypto

g++ -std=c++17 -Wall -pthread crypto.cpp dh.cpp client.cpp -o client -lcrypto

g++ -std=c++17 -Wall -pthread dh.cpp crypto.cpp mitm_proxy.cpp -o mitm_proxy -lcrypto
```

`libssl-dev` must be installed (`sudo apt install -y libssl-dev`).

## Run

```bash
./test_dh                                     # standalone DH sanity check
./server <port>
./client <server_ip> <port> <username>
./mitm_proxy <listen_port> <real_server_ip> <real_server_port>
```