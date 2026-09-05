#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

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

int main(int argc, char** argv) {
    int port = std::atoi(argv[1]);
    std::string rogue_cert_path = argv[2];

    std::string rogue_pem;
    {
        FILE* f = fopen(rogue_cert_path.c_str(), "r");
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) rogue_pem.append(buf, n);
        fclose(f);
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(listen_fd, 1);

    std::cout << "[FAKE SERVER] Listening on port " << port << "...\n";
    int client_fd = accept(listen_fd, nullptr, nullptr);
    std::cout << "[FAKE SERVER] Victim connected. Presenting ROGUE certificate...\n";

    send_framed(client_fd, "CERT|" + rogue_pem);

    std::cout << "[FAKE SERVER] Rogue cert sent. Waiting up to 3s to see if victim sends anything further...\n";

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(client_fd, &fds);
    timeval tv{3, 0};
    int ready = select(client_fd + 1, &fds, nullptr, nullptr, &tv);

    if (ready > 0) {
        uint32_t len_net;
        ssize_t r = recv(client_fd, &len_net, sizeof(len_net), MSG_DONTWAIT);
        if (r > 0) {
            std::cout << "[FAKE SERVER] VICTIM SENT MORE DATA AFTER ROGUE CERT - THIS WOULD BE A BUG!\n";
        } else {
            std::cout << "[FAKE SERVER] Victim closed the connection (recv returned " << r << ").\n";
        }
    } else {
        std::cout << "[FAKE SERVER] No further data received from victim within timeout - "
                     "victim correctly aborted after rejecting the certificate.\n";
    }

    close(client_fd);
    return 0;
}