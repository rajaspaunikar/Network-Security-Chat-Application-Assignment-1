#include "dh.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <iostream>
#include <iomanip>
#include <sstream>

std::string sha256_fingerprint(const std::string& hex_secret) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(hex_secret.data()), hex_secret.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < 8; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

int main() {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = dh_load_prime();
    BIGNUM* g = dh_load_generator();

    std::cout << "Using RFC 3526 Group 14 (2048-bit MODP)\n";
    std::cout << "Generator g = " << dh_bn_to_hex(g) << "\n\n";

    DHKeyPair alice = dh_generate_keypair(p, g, ctx);
    DHKeyPair bob = dh_generate_keypair(p, g, ctx);

    std::cout << "Alice public value A (truncated): " << dh_bn_to_hex(alice.pub).substr(0, 32) << "...\n";
    std::cout << "Bob public value B (truncated):   " << dh_bn_to_hex(bob.pub).substr(0, 32) << "...\n\n";

    BIGNUM* alice_secret = dh_compute_shared_secret(bob.pub, alice.priv, p, ctx);
    BIGNUM* bob_secret = dh_compute_shared_secret(alice.pub, bob.priv, p, ctx);

    std::string alice_fp = sha256_fingerprint(dh_bn_to_hex(alice_secret));
    std::string bob_fp = sha256_fingerprint(dh_bn_to_hex(bob_secret));

    std::cout << "Alice's derived secret fingerprint: " << alice_fp << "\n";
    std::cout << "Bob's derived secret fingerprint:   " << bob_fp << "\n\n";

    if (alice_fp == bob_fp) {
        std::cout << "MATCH: Alice and Bob derived the identical shared secret.\n";
    } else {
        std::cout << "MISMATCH: something is wrong.\n";
    }

    BN_free(p);
    BN_free(g);
    BN_free(alice_secret);
    BN_free(bob_secret);
    dh_free_keypair(alice);
    dh_free_keypair(bob);
    BN_CTX_free(ctx);

    return 0;
}