#include <iostream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>

using namespace std;

unordered_map<string, int> clients;
mutex clients_mutex;

std::string trim(const std::string &s)
{
    size_t start = 0, end = s.size();
    while (start < end && std::isspace(static_cast<unsigned char>(s[start])))
        start++;
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        end--;
    return s.substr(start, end - start);
}

void route_message(const string &from, const string &to, const string &content)
{
    cout << "Inside route_message function\n";

    lock_guard<mutex> lock(clients_mutex);

    for (auto &client : clients)
    {
        cout << "Client: " << client.first << ", FD: " << client.second << "\n";
    }

    auto iterator = clients.find(to);

    if (iterator == clients.end())
        return;

    string wire_msg = "[" + from + "] " + content;

    cout << "Routing message from " << from << " to " << to << ": " << content << "\n";

    send(iterator->second, wire_msg.c_str(), wire_msg.size(), 0);
}

void handle_client(int client_fd)
{

    char buffer[1024];

    int length = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (length <= 0)
    {
        close(client_fd);
        return;
    }

    buffer[length] = '\0';

    string username = trim(string(buffer));

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients[username] = client_fd;
    }

    std::cout << username << " connected.\n";
    std::cout << "DEBUG: username length=" << username.size() << " last char=" << (int)username.back() << "\n";

    while (true)
    {
        length = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        cout << length << "\n";

        if (length <= 0)
            break;

        buffer[length] = '\0';
        string msg(buffer);

        size_t colon = msg.find(':');
        if (colon == string::npos)
            continue;

        std::string to = trim(msg.substr(0, colon));
        string content = msg.substr(colon + 1);

        cout << "Calling route_message with username: " << username << ", to: " << to << ", content: " << content << "\n";
        route_message(username, to, content);
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(username);
    }

    std::cout << username << " disconnected.\n";

    close(client_fd);
}

int main()
{

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(5000);

    bind(server_fd, (sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 5);

    std::cout << "Server listening on port 5000...\n";

    while (true)
    {
        int client_fd = accept(server_fd, nullptr, nullptr);
        std::thread(handle_client, client_fd).detach();
    }
}