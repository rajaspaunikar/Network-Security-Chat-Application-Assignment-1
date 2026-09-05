#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "cert.h"

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

bool recv_framed(int fd, std::string& out) {
    uint32_t len_net;
    if (recv_exact(fd, &len_net, sizeof(len_net)) <= 0) return false;
    uint32_t len = ntohl(len_net);
    out.resize(len);
    if (len == 0) return true;
    return recv_exact(fd, out.data(), len) > 0;
}

std::vector<std::string> parse_frame(const std::string& raw) {
    std::vector<std::string> parts;
    size_t first = raw.find('|');
    if (first == std::string::npos) { parts.push_back(raw); return parts; }
    parts.push_back(raw.substr(0, first));
    parts.push_back(raw.substr(first + 1));
    return parts;
}

int main(int argc, char** argv) {
    int port = std::atoi(argv[1]);
    std::string real_cert_path = argv[2];
    std::string attacker_key_path = argv[3];

    std::string real_cert_pem = read_file_to_string(real_cert_path);
    EVP_PKEY* attacker_key = load_private_key_from_file(attacker_key_path);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(listen_fd, 1);

    std::cout << "[ATTACKER] Listening on port " << port
              << " with the REAL certificate but a DIFFERENT private key...\n";

    int client_fd = accept(listen_fd, nullptr, nullptr);
    std::cout << "[ATTACKER] Victim connected. Sending the genuine, stolen certificate...\n";

    send_framed(client_fd, "CERT|" + real_cert_pem);

    std::string challenge_frame;
    if (!recv_framed(client_fd, challenge_frame)) {
        std::cout << "[ATTACKER] Victim disconnected before sending a challenge.\n";
        return 1;
    }
    auto parts = parse_frame(challenge_frame);
    std::string challenge = parts.size() >= 2 ? parts[1] : "";
    std::cout << "[ATTACKER] Received challenge: " << challenge << "\n";
    std::cout << "[ATTACKER] Signing with MY OWN private key (not the real server's)...\n";

    std::string signature;
    sign_data(attacker_key, challenge, signature);

    std::ostringstream sig_hex;
    for (unsigned char c : signature) sig_hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);

    send_framed(client_fd, "PROOF|" + sig_hex.str());

    std::cout << "[ATTACKER] Forged proof sent. Waiting to see if victim proceeds...\n";

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(client_fd, &fds);
    timeval tv{3, 0};
    int ready = select(client_fd + 1, &fds, nullptr, nullptr, &tv);
    if (ready > 0) {
        char buf[16];
        ssize_t r = recv(client_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (r > 0) {
            std::cout << "[ATTACKER] VICTIM SENT MORE DATA - THIS WOULD BE A BUG!\n";
        } else {
            std::cout << "[ATTACKER] Victim closed the connection (correct - proof rejected).\n";
        }
    } else {
        std::cout << "[ATTACKER] No further data from victim - proof-of-possession check worked.\n";
    }

    close(client_fd);
    return 0;
}