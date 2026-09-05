#pragma once

#include <string>

bool aes_gcm_encrypt(const unsigned char* key, const std::string& plaintext, std::string& out_blob);
bool aes_gcm_decrypt(const unsigned char* key, const std::string& blob, std::string& out_plaintext);