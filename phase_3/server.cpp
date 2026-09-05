#include <iostream>
#include <string>
#include <cstring>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <csignal>
#include <cstdint>
#include <memory>
#include <array>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/bn.h>
#include "dh.h"
#include "crypto.h"
#include "cert.h"

std::mutex log_mutex;

std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&now_c), "%H:%M:%S");
    return oss.str();
}

enum class LogLevel { INFO, WARN, ERR, DEBUG };

void log(LogLevel level, const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::string tag;
    switch (level) {
        case LogLevel::INFO:  tag = "INFO "; break;
        case LogLevel::WARN:  tag = "WARN "; break;
        case LogLevel::ERR:   tag = "ERROR"; break;
        case LogLevel::DEBUG: tag = "DEBUG"; break;
    }
    std::cout << "[" << timestamp() << "] [" << tag << "] " << msg << std::endl;
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

std::mutex send_mutexes_guard;
std::unordered_map<int, std::shared_ptr<std::mutex>> send_mutexes;

std::shared_ptr<std::mutex> get_send_mutex(int fd) {
    std::lock_guard<std::mutex> lock(send_mutexes_guard);
    auto it = send_mutexes.find(fd);
    if (it != send_mutexes.end()) return it->second;
    auto m = std::make_shared<std::mutex>();
    send_mutexes[fd] = m;
    return m;
}

void remove_send_mutex(int fd) {
    std::lock_guard<std::mutex> lock(send_mutexes_guard);
    send_mutexes.erase(fd);
}

bool send_framed(int fd, const std::string& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    if (!send_exact(fd, &len, sizeof(len))) return false;
    return send_exact(fd, payload.data(), payload.size());
}

bool send_framed_safe(int fd, const std::string& payload) {
    auto m = get_send_mutex(fd);
    std::lock_guard<std::mutex> lock(*m);
    return send_framed(fd, payload);
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

bool send_encrypted(int fd, const unsigned char* key, const std::string& payload) {
    std::string blob;
    if (!aes_gcm_encrypt(key, payload, blob)) return false;
    return send_framed_safe(fd, blob);
}

bool recv_encrypted(int fd, const unsigned char* key, std::string& out) {
    std::string blob;
    if (!recv_framed(fd, blob)) return false;
    return aes_gcm_decrypt(key, blob, out);
}

std::unordered_map<std::string, int> clients;
std::mutex clients_mutex;

std::mutex keys_mutex;
std::unordered_map<int, std::array<unsigned char, 32>> client_keys;

void store_key(int fd, const unsigned char* key) {
    std::lock_guard<std::mutex> lock(keys_mutex);
    std::array<unsigned char, 32> arr;
    std::memcpy(arr.data(), key, 32);
    client_keys[fd] = arr;
}

bool get_key(int fd, unsigned char* out) {
    std::lock_guard<std::mutex> lock(keys_mutex);
    auto it = client_keys.find(fd);
    if (it == client_keys.end()) return false;
    std::memcpy(out, it->second.data(), 32);
    return true;
}

void remove_key(int fd) {
    std::lock_guard<std::mutex> lock(keys_mutex);
    client_keys.erase(fd);
}

void debug_print_clients() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto& client : clients) {
        log(LogLevel::DEBUG, "Client: " + client.first + ", FD: " + std::to_string(client.second));
    }
}

void route_message(const std::string& from, const std::string& to, const std::string& content) {
    log(LogLevel::INFO, "[RELAY] " + from + " -> " + to + ": " + content);

    int target_fd = -1;
    int sender_fd = -1;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.find(to);
        if (it != clients.end()) target_fd = it->second;
        auto it2 = clients.find(from);
        if (it2 != clients.end()) sender_fd = it2->second;
    }

    if (target_fd == -1) {
        log(LogLevel::WARN, to + " is not online (message from " + from + " dropped)");
        if (sender_fd != -1) {
            unsigned char key[32];
            if (get_key(sender_fd, key)) {
                send_encrypted(sender_fd, key, "ERROR|" + to + " is not online");
            }
        }
        return;
    }

    unsigned char target_key[32];
    if (get_key(target_fd, target_key)) {
        send_encrypted(target_fd, target_key, "MSG|" + from + "|" + content);
    }
}

void handle_who(int requester_fd, const std::string& requester_name) {
    std::string list;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto& client : clients) {
            if (client.first == requester_name) continue;
            if (!list.empty()) list += ",";
            list += client.first;
        }
    }
    unsigned char key[32];
    if (get_key(requester_fd, key)) {
        send_encrypted(requester_fd, key, "WHO_RESP|" + list);
    }
    log(LogLevel::DEBUG, requester_name + " requested /who -> [" + list + "]");
}

bool perform_dh_handshake(int client_fd, BIGNUM* p, BIGNUM* g, BN_CTX* ctx, BIGNUM*& shared_secret_out) {
    std::string frame;
    if (!recv_framed(client_fd, frame)) return false;

    auto parts = parse_frame(frame);
    if (parts.empty() || parts[0] != "DH_INIT" || parts.size() < 2) return false;

    BIGNUM* client_pub = nullptr;
    if (!BN_hex2bn(&client_pub, parts[1].c_str())) return false;

    DHKeyPair server_kp = dh_generate_keypair(p, g, ctx);

    shared_secret_out = dh_compute_shared_secret(client_pub, server_kp.priv, p, ctx);

    if (!send_framed_safe(client_fd, "DH_RESP|" + dh_bn_to_hex(server_kp.pub))) {
        BN_free(client_pub);
        dh_free_keypair(server_kp);
        return false;
    }

    BN_free(client_pub);
    dh_free_keypair(server_kp);
    return true;
}

void handle_client(int client_fd, BIGNUM* p, BIGNUM* g, const std::string& cert_pem) {
    BN_CTX* ctx = BN_CTX_new();

    if (!send_framed_safe(client_fd, "CERT|" + cert_pem)) {
        close(client_fd);
        BN_CTX_free(ctx);
        return;
    }

    BIGNUM* shared_secret = nullptr;
    if (!perform_dh_handshake(client_fd, p, g, ctx, shared_secret)) {
        log(LogLevel::WARN, "DH handshake failed, dropping connection.");
        close(client_fd);
        BN_CTX_free(ctx);
        return;
    }

    log(LogLevel::INFO, "DH shared secret fingerprint: " + dh_sha256_fingerprint(shared_secret));

    unsigned char aes_key[32];
    dh_derive_aes_key(shared_secret, aes_key);
    store_key(client_fd, aes_key);

    std::string frame;
    if (!recv_encrypted(client_fd, aes_key, frame)) {
        BN_free(shared_secret);
        remove_key(client_fd);
        BN_CTX_free(ctx);
        close(client_fd);
        return;
    }

    auto reg_parts = parse_frame(frame);
    if (reg_parts.empty() || reg_parts[0] != "REGISTER" || reg_parts.size() < 2 || reg_parts[1].empty()) {
        send_encrypted(client_fd, aes_key, "ERROR|Expected REGISTER|<username> as first message");
        BN_free(shared_secret);
        remove_key(client_fd);
        BN_CTX_free(ctx);
        close(client_fd);
        return;
    }
    std::string username = reg_parts[1];

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(username)) {
            send_encrypted(client_fd, aes_key, "ERROR|username already taken");
            BN_free(shared_secret);
            remove_key(client_fd);
            BN_CTX_free(ctx);
            close(client_fd);
            return;
        }
        clients[username] = client_fd;
    }
    log(LogLevel::INFO, username + " connected.");
    send_encrypted(client_fd, aes_key, "REGISTER_OK|" + username);
    debug_print_clients();

    while (recv_encrypted(client_fd, aes_key, frame)) {
        auto parts = parse_frame(frame);
        if (parts.empty()) continue;

        const std::string& type = parts[0];

        if (type == "MSG" && parts.size() >= 3) {
            route_message(username, parts[1], parts[2]);
        }
        else if (type == "WHO") {
            handle_who(client_fd, username);
        }
        else if (type == "QUIT") {
            log(LogLevel::INFO, username + " sent QUIT.");
            break;
        }
        else {
            log(LogLevel::WARN, "Unrecognized frame from " + username + ": " + frame);
        }
    }
    log(LogLevel::INFO, username + " connection closed.");

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(username);
    }
    remove_send_mutex(client_fd);
    remove_key(client_fd);
    BN_free(shared_secret);
    BN_CTX_free(ctx);
    close(client_fd);
    log(LogLevel::INFO, username + " disconnected.");
    debug_print_clients();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }
    int port = std::atoi(argv[1]);

    signal(SIGPIPE, SIG_IGN);

    BIGNUM* p = dh_load_prime();
    BIGNUM* g = dh_load_generator();
    std::string cert_pem = read_file_to_string("server_cert.pem");
    if (cert_pem.empty()) {
        std::cerr << "Could not read server_cert.pem\n";
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 8) < 0) {
        perror("listen");
        return 1;
    }

    log(LogLevel::INFO, "Server listening on port " + std::to_string(port) + " ...");

    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        log(LogLevel::INFO, "New TCP connection from " + std::string(ip));

        std::thread(handle_client, client_fd, p, g, cert_pem).detach();
    }

    BN_free(p);
    BN_free(g);
    close(server_fd);
    return 0;
}