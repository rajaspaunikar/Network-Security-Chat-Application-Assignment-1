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



static const size_t MAX_MSG_SIZE = 1 << 20; // CHANGED: 1 MB sanity cap - rejects a corrupt/garbage length header instead of trying to allocate an insane amount of memory


ssize_t recv_exact(int fd, void* buf, size_t n) {
    size_t got = 0;
    char* p = static_cast<char*>(buf);
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r <= 0) return r; // 0 = peer closed cleanly, <0 = error
        got += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(got);
}


bool send_exact(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    const char* p = static_cast<const char*>(buf);
    while (sent < n) {
        ssize_t s = send(fd, p + sent, n - sent, MSG_NOSIGNAL); // Do not raise SIGPIPE if connection already closed
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
    if (len == 0) return true; // an empty payload is a valid (if unusual) frame
    return recv_exact(fd, out.data(), len) > 0;
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
        if (sender_fd != -1) send_framed_safe(sender_fd, "ERROR|" + to + " is not online"); // CHANGED: safe_send -> send_framed
        return;
    }

    send_framed_safe(target_fd, "MSG|" + from + "|" + content); // CHANGED: safe_send -> send_framed
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
    send_framed_safe(requester_fd, "WHO_RESP|" + list); // CHANGED: safe_send -> send_framed
    log(LogLevel::DEBUG, requester_name + " requested /who -> [" + list + "]");
}

//Per client thread
void handle_client(int client_fd) {

    std::string frame;
    if (!recv_framed(client_fd, frame)) { close(client_fd); return; }

    auto reg_parts = parse_frame(frame);
    if (reg_parts.empty() || reg_parts[0] != "REGISTER" || reg_parts.size() < 2 || reg_parts[1].empty()) {
        send_framed_safe(client_fd, "ERROR|Expected REGISTER|<username> as first message"); // CHANGED: safe_send -> send_framed
        close(client_fd);
        return;
    }
    std::string username = reg_parts[1];

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(username)) {
            send_framed_safe(client_fd, "ERROR|username already taken"); // CHANGED: safe_send -> send_framed
            close(client_fd);
            return;
        }
        clients[username] = client_fd;
    }
    log(LogLevel::INFO, username + " connected.");
    send_framed_safe(client_fd, "REGISTER_OK|" + username); // CHANGED: safe_send -> send_framed
    debug_print_clients();

    // CHANGED: loop condition now calls recv_framed() directly instead of
    // raw recv() + manual null-termination. Each successful call returns one
    // complete frame in `frame`, regardless of how many TCP segments/recv()
    // calls it took under the hood to assemble it.
    while (recv_framed(client_fd, frame)) {
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
    log(LogLevel::INFO, username + " connection closed."); // CHANGED: moved out of the old raw-recv branch since recv_framed's loop condition now handles the "connection closed" exit implicitly

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(username);
    }
    remove_send_mutex(client_fd); // CHANGED (concurrency fix): clean up this fd's send mutex now that the connection is done
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