#include "dh.h"
#include "dh_group_14.h"
#include <cstring>

BIGNUM* dh_load_prime() {
    BIGNUM* p = nullptr;
    BN_hex2bn(&p, DH_GROUP14_PRIME_HEX);
    return p;
}

BIGNUM* dh_load_generator() {
    BIGNUM* g = nullptr;
    BN_hex2bn(&g, DH_GROUP14_GENERATOR_HEX);
    return g;
}

DHKeyPair dh_generate_keypair(const BIGNUM* p, const BIGNUM* g, BN_CTX* ctx) {
    DHKeyPair kp;
    kp.priv = BN_new();
    kp.pub = BN_new();

    BN_rand_range(kp.priv, p);

    BN_mod_exp(kp.pub, g, kp.priv, p, ctx);

    return kp;
}

BIGNUM* dh_compute_shared_secret(const BIGNUM* their_pub, const BIGNUM* my_priv, const BIGNUM* p, BN_CTX* ctx) {
    BIGNUM* secret = BN_new();
    BN_mod_exp(secret, their_pub, my_priv, p, ctx);
    return secret;
}

std::string dh_bn_to_hex(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

void dh_free_keypair(DHKeyPair& kp) {
    BN_free(kp.priv);
    BN_free(kp.pub);
    kp.priv = nullptr;
    kp.pub = nullptr;
}