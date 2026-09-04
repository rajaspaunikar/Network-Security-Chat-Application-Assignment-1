# Phase 2 - Client-Server Confidentiality via Diffie-Hellman

## Files

- `dh_group.h` - RFC 3526 Group 14 (2048-bit MODP) prime and generator constants.
- `dh.h` / `dh.cpp` - Diffie-Hellman key generation, shared secret computation,
  fingerprint, and AES key derivation, implemented from scratch using OpenSSL's
  `BIGNUM` API (`BN_mod_exp` for modular exponentiation).
- `crypto.h` / `crypto.cpp` - AES-256-GCM encrypt/decrypt using OpenSSL's EVP API.
- `server.cpp` - chat server. Performs an independent DH exchange with each
  connecting client, derives a per-connection AES key, and encrypts all
  traffic (including registration) with AES-GCM.
- `client.cpp` - chat client. Same DH + AES-GCM handshake as the server, plus
  the `@username`, `/chat`, `/who`, `/quit` command interface from Phase 1.
- `mitm_proxy.cpp` - standalone attacker tool ("Mallory"). Performs two
  independent DH exchanges - one posing as the server to a victim client, one
  posing as a client to the real server - and transparently relays traffic
  between them, decrypting and re-encrypting at each hop.
- `test_dh.cpp` - standalone test simulating two parties (Alice, Bob) deriving
  a shared secret in one process, with no networking involved.

## Build

```
g++ -std=c++17 -Wall dh.cpp test_dh.cpp -o test -lcrypto

g++ -std=c++17 -Wall -pthread crypto.cpp dh.cpp server.cpp -o server -lcrypto

g++ -std=c++17 -Wall -pthread crypto.cpp dh.cpp client.cpp -o client -lcrypto

g++ -std=c++17 -Wall -pthread dh.cpp crypto.cpp mitm_proxy.cpp -o mitm_proxy -lcrypto
```

`libssl-dev` must be installed for these to compile (`sudo apt install -y libssl-dev`).

## Run

**Standalone DH test (no networking, sanity check only):**
```
./test
```

**Server:**
```
./server <port>
```

**Client:**
```
./client <server_ip> <port> <username>
```

**MITM proxy (Mallory):**
```
./mitm_proxy <listen_port> <real_server_ip> <real_server_port>
```
To attack a victim, point their client at Mallory's address/port instead of
the real server's:
```
./client <mallory_ip> <mallory_listen_port> <username>
```
Mallory relays the session transparently to the real server, so the victim's
chat still works normally end-to-end, while every message is visible to
Mallory in plaintext.

## Notes

- The DH handshake (`DH_INIT`/`DH_RESP`) is unencrypted by necessity - no key
  exists until it completes. Every message after that, including the
  `REGISTER`/`REGISTER_OK` exchange, is encrypted with AES-GCM.
- The DH shared secret is never used directly as the AES key. It is hashed
  with SHA-256 first (`dh_derive_aes_key`) - see report for why.
- Both client and server print a SHA-256 fingerprint of the shared secret
  after the handshake, for verification that both sides derived the same
  value, without ever printing the secret itself.