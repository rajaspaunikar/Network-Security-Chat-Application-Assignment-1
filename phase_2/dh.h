#pragma once

#include <openssl/bn.h>
#include <string>

struct DHKeyPair {
    BIGNUM* priv;
    BIGNUM* pub;
};

DHKeyPair dh_generate_keypair(const BIGNUM* p, const BIGNUM* g, BN_CTX* ctx);
BIGNUM* dh_compute_shared_secret(const BIGNUM* their_pub, const BIGNUM* my_priv, const BIGNUM* p, BN_CTX* ctx);
BIGNUM* dh_load_prime();
BIGNUM* dh_load_generator();
std::string dh_bn_to_hex(const BIGNUM* bn);
void dh_free_keypair(DHKeyPair& kp);