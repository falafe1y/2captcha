#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <mutex>
#include <thread>

using boost::asio::ip::tcp;

struct Proxy {
    std::string ip;
    int port;
    std::string protocol;
    std::string username;
    std::string password;
};

std::vector<Proxy> proxies;
size_t current_proxy_index = 0;
std::mutex proxy_mutex;

// Load proxies from a file
void load_proxies(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        Proxy proxy;

        // Remove protocol (http://, socks5://)
        size_t protocol_pos = line.find("://");
        if (protocol_pos != std::string::npos) {
            proxy.protocol = line.substr(0, protocol_pos);
            line = line.substr(protocol_pos + 3);   // Remove protocol part
        }

        size_t auth_pos = line.find('@');
        if (auth_pos != std::string::npos) {
            std::string auth = line.substr(0, auth_pos);    // user:pass
            size_t colon_pos = auth.find(':');
            if (colon_pos != std::string::npos) {
                proxy.username = auth.substr(0, colon_pos);
                proxy.password = auth.substr(colon_pos + 1);
            }
            line = line.substr(auth_pos + 1);   // Remove user:pass part
        }

        // Find separator between IP and port
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            proxy.ip = line.substr(0, pos); // IP
            proxy.port = std::stoi(line.substr(pos + 1));   // Port
            proxies.push_back(proxy);
        }
    }
}

// Select the next proxy (round-robin)
Proxy get_next_proxy() {
    std::lock_guard<std::mutex> lock(proxy_mutex);
    if (proxies.empty()) throw std::runtime_error("No proxies available");
    Proxy proxy = proxies[current_proxy_index];
    current_proxy_index = (current_proxy_index + 1) % proxies.size();
    return proxy;
}

size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

// Handle the request through a proxy
std::string handle_request(const std::string& url, const std::string& proxy_with_auth) {
    CURL *curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy_with_auth.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Curl error: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    return response;
}

// Handle connection with the client
void handle_client(tcp::socket socket) {
    try {
        char data[1024];
        size_t length = socket.read_some(boost::asio::buffer(data));
        std::string request(data, length);

        // Pasrsing string "logn + password + url"
        std::istringstream iss(request);
        std::string login, password, url;
        iss >> login >> password;
        std::getline(iss, url);
        if (!url.empty() && url[0] == ' ') url.erase(0, 1); // Del space before URL

        // Proxy without data for auth
        Proxy proxy = get_next_proxy();

        // New proxy with auth
        std::string proxy_with_auth = proxy.protocol + "://" + login + ":" + password + "@" + proxy.ip + ":" + std::to_string(proxy.port);
        std::cout << "Proxy: " << proxy_with_auth << '\n';

        std::string response = handle_request(url, proxy_with_auth);
        boost::asio::write(socket, boost::asio::buffer(response));
    } catch (const std::exception& e) {
        std::cerr << "Error processing request: " << e.what() << std::endl;
    }
}

void start_server(int port) {
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
    std::cout << "Server is listening on port " << port << "...\n";
    while (true) {
        tcp::socket socket(io_context);
        acceptor.accept(socket);
        std::thread(handle_client, std::move(socket)).detach();
    }
}

int main() {
    load_proxies("http.txt");
    load_proxies("socks5.txt");
    if (proxies.empty()) {
        std::cerr << "No proxies loaded!\n";
        return 1;
    }
    const int port = 8080;
    start_server(port);
    return 0;
}
