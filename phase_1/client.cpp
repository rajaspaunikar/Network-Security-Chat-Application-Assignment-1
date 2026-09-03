#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <atomic>
#include <thread>
#include <cctype>
#include <csignal>

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

bool safe_send(int fd, const std::string& msg) {
    ssize_t n = send(fd, msg.c_str(), msg.size(), MSG_NOSIGNAL);
    return n == static_cast<ssize_t>(msg.size());
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
    char buf[4096];
    while (running) {
        int n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            if (running) std::cout << "\n[Disconnected from server]\n";
            running = false;
            break;
        }
        buf[n] = '\0';
        auto parts = parse_frame(std::string(buf));
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
        safe_send(sockfd, "MSG|" + current_partner + "|" + content);
    }
    else if (line.rfind("/chat ", 0) == 0) {   // starts with "/chat "
        current_partner = trim(line.substr(6));
        std::cout << "Now chatting with " << current_partner << "\n";
    }
    else if (line == "/who") {
        safe_send(sockfd, "WHO|");
    }
    else if (line == "/quit") {
        safe_send(sockfd, "QUIT|");
        return false; // signal caller to stop
    }
    else {
        if (current_partner.empty()) {
            std::cout << "No chat partner selected. Use @username or /chat username first.\n";
        } else {
            safe_send(sockfd, "MSG|" + current_partner + "|" + line);
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

    if (!safe_send(sockfd, "REGISTER|" + my_username)) {
        std::cerr << "Failed to send registration\n";
        return 1;
    }
    char buf[4096];
    int n = recv(sockfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        std::cerr << "Server closed connection during registration\n";
        return 1;
    }
    buf[n] = '\0';
    auto parts = parse_frame(std::string(buf));
    if (parts.empty() || parts[0] != "REGISTER_OK") {
        std::cerr << "Registration failed: " << std::string(buf) << "\n";
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
