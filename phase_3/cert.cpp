#include "cert.h"
#include <openssl/pem.h>
#include <fstream>
#include <sstream>

std::string read_file_to_string(const std::string& path) {
    std::ifstream f(path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

X509* cert_load_from_pem_string(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

X509* cert_load_from_file(const std::string& path) {
    std::string pem = read_file_to_string(path);
    return cert_load_from_pem_string(pem);
}

std::string cert_to_pem_string(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

bool cert_verify_chain(X509* cert, X509* ca_cert) {
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_cert);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);

    int result = X509_verify_cert(ctx);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return result == 1;
}

std::string cert_get_cn(X509* cert) {
    X509_NAME* name = X509_get_subject_name(cert);
    char cn[256];
    X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));
    return std::string(cn);
}