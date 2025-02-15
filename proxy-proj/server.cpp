#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <mutex>

using boost::asio::ip::tcp;

struct Proxy {
    std::string ip;
    int port;
    std::string protocol;
};

std::vector<Proxy> proxies;
size_t current_proxy_index = 0;
std::mutex proxy_mutex;

// Load proxies from a file
void load_proxies(const std::string& filename, const std::string& protocol) {
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        // Remove protocol (http://, socks5://)
        size_t protocol_pos = line.find("://");
        if (protocol_pos != std::string::npos) {
            line = line.substr(protocol_pos + 3);
        }

        // Find separator between IP and port
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            Proxy proxy;
            proxy.ip = line.substr(0, pos); // IP address
            proxy.port = std::stoi(line.substr(pos + 1)); // Port
            proxy.protocol = protocol;
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
    std::cout << "Proxy protocol: " << proxy.protocol << "\n";
    return proxy;
}

size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

// Handle the request through a proxy
std::string handle_request(const std::string &url) {
    Proxy proxy = get_next_proxy();
    CURL *curl;
    CURLcode res;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set proxy
        if (proxy.protocol == "http") {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy.ip.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxy.port);
        } else if (proxy.protocol == "socks5") {
            std::string proxy_address = proxy.ip + ":" + std::to_string(proxy.port);
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_address.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        }

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Curl error: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return response;
}

void start_server(int port, std::string url) {
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
    std::cout << "Server is listening on port " << port << "...\n";

    while (true) {
        tcp::socket socket(io_context);
        acceptor.accept(socket);
        std::cout << "Connected...\n";
        try {
            char data[512];
            size_t length = socket.read_some(boost::asio::buffer(data));
            std::string client_request(data, length);
            std::cout << "Request from client: " << client_request << "\n";

            std::cout << "URL: " << url << "\n";

            std::string response = handle_request(url);
            std::cout << "------------------\nResponse from proxy:\n\n" << response << std::endl;
            boost::asio::write(socket, boost::asio::buffer(response));
            socket.close();
        } catch (const std::exception& e) {
            std::cerr << "Error processing request: " << e.what() << std::endl;
        }
    }
}

int main() {
    load_proxies("http.txt", "http");
    load_proxies("socks5.txt", "socks5");
    if (proxies.empty()) {
        std::cerr << "No proxies loaded!\n";
        return 1;
    }
    const int port = 8080;
    start_server(port, "https://ip.oxylabs.io");
    return 0;
}
