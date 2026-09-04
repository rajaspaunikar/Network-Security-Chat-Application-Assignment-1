#include "crypto.h"
#include <iostream>
#include <cstring>

int main() {
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = static_cast<unsigned char>(i);

    std::string plaintext = "MSG|bob|hello this is a test message";

    std::string blob;
    if (!aes_gcm_encrypt(key, plaintext, blob)) {
        std::cout << "Encryption failed\n";
        return 1;
    }
    std::cout << "Original plaintext:  " << plaintext << "\n";
    std::cout << "Encrypted blob size: " << blob.size() << " bytes\n\n";

    std::string decrypted;
    if (!aes_gcm_decrypt(key, blob, decrypted)) {
        std::cout << "Decryption failed unexpectedly\n";
        return 1;
    }
    std::cout << "Decrypted plaintext: " << decrypted << "\n";
    std::cout << (decrypted == plaintext ? "ROUND TRIP OK\n\n" : "ROUND TRIP MISMATCH\n\n");

    std::string tampered = blob;
    tampered[tampered.size() - 1] ^= 0xFF;

    std::string tampered_result;
    bool tamper_decrypt_ok = aes_gcm_decrypt(key, tampered, tampered_result);

    std::cout << "Tamper test: flipped last byte of ciphertext.\n";
    if (!tamper_decrypt_ok) {
        std::cout << "TAMPER CORRECTLY REJECTED (GCM authentication failed as expected)\n";
    } else {
        std::cout << "TAMPER NOT DETECTED - THIS IS A BUG\n";
    }

    return 0;
}