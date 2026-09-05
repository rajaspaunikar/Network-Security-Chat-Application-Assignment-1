#pragma once

#include <openssl/x509.h>
#include <string>

X509* cert_load_from_pem_string(const std::string& pem);
X509* cert_load_from_file(const std::string& path);
std::string cert_to_pem_string(X509* cert);
bool cert_verify_chain(X509* cert, X509* ca_cert);
std::string cert_get_cn(X509* cert);
EVP_PKEY* cert_get_pubkey(X509* cert);
EVP_PKEY* load_private_key_from_file(const std::string& path);
bool sign_data(EVP_PKEY* privkey, const std::string& data, std::string& signature_out);
bool verify_signature(EVP_PKEY* pubkey, const std::string& data, const std::string& signature);
std::string read_file_to_string(const std::string& path);