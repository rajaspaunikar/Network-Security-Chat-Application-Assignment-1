#!/bin/bash
set -e

mkdir -p certs

openssl genrsa -out certs/ca_key.pem 4096

openssl req -x509 -new -nodes -key certs/ca_key.pem -sha256 -days 365 \
  -subj "/C=IN/O=CS6008-Assignment1/CN=MyChatCA" \
  -out certs/ca_cert.pem

openssl genrsa -out certs/server_key.pem 2048

openssl req -new -key certs/server_key.pem \
  -subj "/C=IN/O=CS6008-Assignment1/CN=ChatServer" \
  -out certs/server.csr

openssl x509 -req -in certs/server.csr -CA certs/ca_cert.pem -CAkey certs/ca_key.pem \
  -CAcreateserial -days 365 -sha256 \
  -out certs/server_cert.pem

openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

echo ""
echo "PKI setup complete. All files written to certs/"
echo "  certs/ca_key.pem      - CA private key (keep secret, never share)"
echo "  certs/ca_cert.pem      - CA root certificate (share with clients to trust)"
echo "  certs/server_key.pem   - server private key (keep secret, server only)"
echo "  certs/server_cert.pem  - server certificate, signed by the CA (send to clients)"