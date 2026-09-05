#include "dh.h"
#include "dh_group_14.h"
#include <cstring>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>

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

std::string dh_sha256_fingerprint(const BIGNUM* secret) {
    std::string hex = dh_bn_to_hex(secret);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(hex.data()), hex.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < 8; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

void dh_derive_aes_key(const BIGNUM* secret, unsigned char* key_out_32bytes) {
    int byte_len = BN_num_bytes(secret);
    std::vector<unsigned char> raw(byte_len);
    BN_bn2bin(secret, raw.data());
    SHA256(raw.data(), raw.size(), key_out_32bytes);
}