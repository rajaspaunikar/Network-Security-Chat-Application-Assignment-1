#!/bin/bash
set -e

openssl genrsa -out ca_key.pem 4096

openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 \
  -subj "/C=IN/O=CS6008-Assignment1/CN=MyChatCA" \
  -out ca_cert.pem

openssl genrsa -out server_key.pem 2048

openssl req -new -key server_key.pem \
  -subj "/C=IN/O=CS6008-Assignment1/CN=ChatServer" \
  -out server.csr

openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -days 365 -sha256 \
  -out server_cert.pem

openssl verify -CAfile ca_cert.pem server_cert.pem

echo ""
echo "PKI setup complete."
echo "  ca_key.pem      - CA private key (keep secret, never share)"
echo "  ca_cert.pem      - CA root certificate (share with clients to trust)"
echo "  server_key.pem   - server private key (keep secret, server only)"
echo "  server_cert.pem  - server certificate, signed by the CA (send to clients)"