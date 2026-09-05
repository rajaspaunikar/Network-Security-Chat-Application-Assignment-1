#include "cert.h"
#include <iostream>

int main() {
    X509* ca_cert = cert_load_from_file("ca_cert.pem");
    X509* server_cert = cert_load_from_file("server_cert.pem");

    std::cout << "Server cert CN: " << cert_get_cn(server_cert) << "\n";

    bool valid = cert_verify_chain(server_cert, ca_cert);
    std::cout << "Legitimate server cert against our CA: "
              << (valid ? "VALID" : "REJECTED") << "\n\n";

    system("openssl genrsa -out /tmp/rogue_key.pem 2048 2>/dev/null");
    system("openssl req -x509 -new -nodes -key /tmp/rogue_key.pem -days 365 "
           "-subj \"/CN=ChatServer\" -out /tmp/rogue_cert.pem 2>/dev/null");

    X509* rogue_cert = cert_load_from_file("/tmp/rogue_cert.pem");
    std::cout << "Rogue cert CN (Mallory's forged cert, same CN, different key): "
              << cert_get_cn(rogue_cert) << "\n";

    bool rogue_valid = cert_verify_chain(rogue_cert, ca_cert);
    std::cout << "Rogue self-signed cert against our real CA: "
              << (rogue_valid ? "VALID (BUG!)" : "REJECTED (correct)") << "\n";

    return 0;
}