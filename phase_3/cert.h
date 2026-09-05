#pragma once

#include <openssl/x509.h>
#include <string>

X509* cert_load_from_pem_string(const std::string& pem);
X509* cert_load_from_file(const std::string& path);
std::string cert_to_pem_string(X509* cert);
bool cert_verify_chain(X509* cert, X509* ca_cert);
std::string cert_get_cn(X509* cert);
std::string read_file_to_string(const std::string& path);