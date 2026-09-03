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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string trim(const std::string& s) {
    size_t start = 0, end = s.size();
    while (start < end && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

// Splits "TYPE|field1|field2" into up to 3 parts.
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
    ssize_t n = send(fd, msg.c_str(), msg.size(), MSG_NOSIGNAL); //Do not raise SIGPIPE if connection already closed
    return n == static_cast<ssize_t>(msg.size());
}


std::unordered_map<std::string, int> clients;
std::mutex clients_mutex;

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
        if (sender_fd != -1) safe_send(sender_fd, "ERROR|" + to + " is not online");
        return;
    }

    safe_send(target_fd, "MSG|" + from + "|" + content);
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
    safe_send(requester_fd, "WHO_RESP|" + list);
    log(LogLevel::DEBUG, requester_name + " requested /who -> [" + list + "]");
}

//Per client thread
void handle_client(int client_fd) {
    char buf[4096];
    int n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';

    auto reg_parts = parse_frame(std::string(buf));
    if (reg_parts.empty() || reg_parts[0] != "REGISTER" || reg_parts.size() < 2 || reg_parts[1].empty()) {
        safe_send(client_fd, "ERROR|Expected REGISTER|<username> as first message");
        close(client_fd);
        return;
    }
    std::string username = reg_parts[1];

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(username)) {
            safe_send(client_fd, "ERROR|username already taken");
            close(client_fd);
            return;
        }
        clients[username] = client_fd;
    }
    log(LogLevel::INFO, username + " connected.");
    safe_send(client_fd, "REGISTER_OK|" + username);
    debug_print_clients();

    while (true) {
        n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            log(LogLevel::INFO, username + " connection closed.");
            break;
        }
        buf[n] = '\0';
        std::string raw(buf);
        auto parts = parse_frame(raw);
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
            log(LogLevel::WARN, "Unrecognized frame from " + username + ": " + raw);
        }
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(username);
    }
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

        std::thread(handle_client, client_fd).detach();
    }

    close(server_fd);
    return 0;
}
