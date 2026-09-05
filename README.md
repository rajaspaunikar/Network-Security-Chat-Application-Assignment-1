# CS6008 - Network Security: Secure Chat Application

A one-to-one chat application built over TCP sockets in C/C++, progressively
hardened across five phases - each phase adds exactly one security property
on top of the last, and is attacked (by a tool built as part of the
assignment) before being trusted.

## Repository

```
https://github.com/rajaspaunikar/Network-Security-Chat-Application-Assignment-1
```

## VM Topology

| VM | Role | IP Address |
|---|---|---|
| Server | Chat server + Certificate Authority (Phase 3+) | 10.0.2.6 |
| Client 1 | Chat client (C1) | 10.0.2.7 |
| Client 2 | Chat client (C2) | 10.0.2.5 |
| Mallory  | MITM attack proxy| 10.0.2.8 |

All four VMs run Ubuntu on the same virtual network (VirtualBox NAT
Network), verified reachable via `ping` before any application traffic.

## Phase Overview

| Phase | Directory | Adds |
|---|---|---|
| 1 | `phase1/` | Baseline TCP chat, no security |
| 2 | `phase2/` | Client-server confidentiality via from-scratch Diffie-Hellman + AES-256-GCM |
| 3 | `phase3/` | Server authentication via a minimal PKI (CA, certificates, proof-of-possession) |
| 4 | `phase4/` | End-to-end encryption directly between clients, invisible to the server |
| 5 | `phase5/` | Forward secrecy via automatic 60-second key rotation |

Each phase directory is independently buildable and contains its own
`README.md` with exact build/run instructions, and a `Makefile` where
applicable.

## Build Requirements

- C++17, POSIX sockets
- OpenSSL development headers (`libssl-dev`)

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

## Quick Start (per phase)

```bash
cd phaseN/
./setup_ca.sh   # phase3 onward only - generates CA + server certificate
make
./server <port>                              # on the Server VM
./client <server_ip> <port> <username>        # on each Client VM
```

See each phase's own `README.md` for phase-specific programs (e.g.
`mitm_proxy` in phase2/phase3, `/e2e` usage in phase4/phase5).

## Report

The full written report, covering implementation details, verification
evidence, and required written answers for every phase, is submitted
separately as a PDF alongside this repository.