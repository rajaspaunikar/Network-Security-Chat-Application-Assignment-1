#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <atomic>
#include <thread>
#include <cctype>
#include <csignal>
#include <cstdint>  

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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



// Wire format: [4 bytes: payload length, network byte order][payload]
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Client-local state
// ---------------------------------------------------------------------------
std::string current_partner;
std::atomic<bool> running{true};

// ---------------------------------------------------------------------------
// Receiver thread: prints whatever the server sends us (chat messages,
// /who responses, errors) while the main thread waits on stdin.
// ---------------------------------------------------------------------------
void receiver_loop(int sockfd) {

    std::string frame;
    while (running) {
        if (!recv_framed(sockfd, frame)) {
            if (running) std::cout << "\n[Disconnected from server]\n";
            running = false;
            break;
        }
        auto parts = parse_frame(frame);
        if (parts.empty()) continue;

        const std::string& type = parts[0];
        if (type == "MSG" && parts.size() >= 3) {
            std::cout << "\n[" << parts[1] << "] " << parts[2] << "\n> " << std::flush;
        }
        else if (type == "WHO_RESP") {
            std::string list = parts.size() >= 2 ? parts[1] : "";
            std::cout << "\nOnline users: " << (list.empty() ? "(none)" : list) << "\n> " << std::flush;
        }
        else if (type == "ERROR") {
            std::string msg = parts.size() >= 2 ? parts[1] : "";
            std::cout << "\n[ERROR] " << msg << "\n> " << std::flush;
        }
    }
}

// ---------------------------------------------------------------------------
// Command interface (§1.3): @username, /chat, /who, /quit
// ---------------------------------------------------------------------------
bool process_user_input(int sockfd, const std::string& line) {
    if (line.empty()) return true;

    if (line[0] == '@') {
        size_t space = line.find(' ');
        if (space == std::string::npos) {
            std::cout << "Usage: @username message\n";
            return true;
        }
        current_partner = line.substr(1, space - 1);
        std::string content = line.substr(space + 1);
        send_framed(sockfd, "MSG|" + current_partner + "|" + content); // CHANGED: safe_send -> send_framed
    }
    else if (line.rfind("/chat ", 0) == 0) {   // starts with "/chat "
        current_partner = trim(line.substr(6));
        std::cout << "Now chatting with " << current_partner << "\n";
    }
    else if (line == "/who") {
        send_framed(sockfd, "WHO|"); // CHANGED: safe_send -> send_framed
    }
    else if (line == "/quit") {
        send_framed(sockfd, "QUIT|"); // CHANGED: safe_send -> send_framed
        return false; // signal caller to stop
    }
    else {
        if (current_partner.empty()) {
            std::cout << "No chat partner selected. Use @username or /chat username first.\n";
        } else {
            send_framed(sockfd, "MSG|" + current_partner + "|" + line); // CHANGED: safe_send -> send_framed
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username>\n";
        return 1;
    }
    std::string server_ip = argv[1];
    int port = std::atoi(argv[2]);
    std::string my_username = argv[3];

    signal(SIGPIPE, SIG_IGN);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP: " << server_ip << "\n";
        return 1;
    }

    if (connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    if (!send_framed(sockfd, "REGISTER|" + my_username)) { // CHANGED: safe_send -> send_framed
        std::cerr << "Failed to send registration\n";
        return 1;
    }


    std::string reply;
    if (!recv_framed(sockfd, reply)) {
        std::cerr << "Server closed connection during registration\n";
        return 1;
    }
    auto parts = parse_frame(reply);
    if (parts.empty() || parts[0] != "REGISTER_OK") {
        std::cerr << "Registration failed: " << reply << "\n";
        close(sockfd);
        return 1;
    }
    std::cout << "Registered as " << my_username << ". Connected to " << server_ip << ":" << port << "\n";
    std::cout << "Commands: @username message | /chat username | /who | /quit\n";

    std::thread rx(receiver_loop, sockfd);

    std::string line;
    std::cout << "> " << std::flush;
    while (running && std::getline(std::cin, line)) {
        bool keep_going = process_user_input(sockfd, line);
        if (!keep_going) break;
        if (running) std::cout << "> " << std::flush;
    }

    running = false;
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    if (rx.joinable()) rx.join();
    return 0;
}