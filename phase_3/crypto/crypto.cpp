#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

static const int NONCE_LEN = 12;
static const int TAG_LEN = 16;

bool aes_gcm_encrypt(const unsigned char* key, const std::string& plaintext, std::string& out_blob) {
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                           reinterpret_cast<const unsigned char*>(plaintext.data()),
                           static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    out_blob.clear();
    out_blob.append(reinterpret_cast<char*>(nonce), NONCE_LEN);
    out_blob.append(reinterpret_cast<char*>(tag), TAG_LEN);
    out_blob.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    return true;
}

bool aes_gcm_decrypt(const unsigned char* key, const std::string& blob, std::string& out_plaintext) {
    if (blob.size() < static_cast<size_t>(NONCE_LEN + TAG_LEN)) return false;

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob.data());
    const unsigned char* tag = reinterpret_cast<const unsigned char*>(blob.data() + NONCE_LEN);
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(blob.data() + NONCE_LEN + TAG_LEN);
    int ciphertext_len = static_cast<int>(blob.size() - NONCE_LEN - TAG_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<unsigned char*>(tag));

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) return false;

    plaintext_len += len;
    out_plaintext.assign(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    return true;
}