#include "cert.h"
#include <iostream>

int main() {
    X509* server_cert = cert_load_from_file("server_cert.pem");
    EVP_PKEY* real_server_key = load_private_key_from_file("server_key.pem");
    EVP_PKEY* cert_pubkey = cert_get_pubkey(server_cert);

    std::string challenge = "handshake_nonce_abc123";

    std::string signature;
    sign_data(real_server_key, challenge, signature);

    bool ok = verify_signature(cert_pubkey, challenge, signature);
    std::cout << "Legitimate server (real private key) signs challenge: "
              << (ok ? "VERIFIED - proof of possession succeeds" : "FAILED") << "\n\n";

    system("openssl genrsa -out /tmp/attacker_key.pem 2048 2>/dev/null");
    EVP_PKEY* attacker_key = load_private_key_from_file("/tmp/attacker_key.pem");

    std::string forged_signature;
    sign_data(attacker_key, challenge, forged_signature);

    bool attacker_ok = verify_signature(cert_pubkey, challenge, forged_signature);
    std::cout << "Attacker (has server_cert.pem, but NOT server_key.pem, signs with own key): "
              << (attacker_ok ? "VERIFIED (BUG!)" : "REJECTED (correct)") << "\n";

    return 0;
}