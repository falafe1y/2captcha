#include <mutex>
#include <thread>
#include <vector>
#include <random>
#include <chrono>
#include <format>
#include <sstream>
#include <fstream>
#include <iostream>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
 
using namespace boost::asio;
using ip::tcp;

std::mutex mutex;

struct Proxy {
    std::string IP;
    std::string port;
    std::string login;
    std::string password;
};

// Get random proxy from proxies list
Proxy get_proxy() {
    std::vector<Proxy> proxies;
    std::ifstream in("proxies.txt");

    if (!in.is_open()) {
        std::cerr << "Failed to open proxies.txt" << std::endl;
        return Proxy();
    }

    std::string line;
    while (std::getline(in, line)) {
        std::stringstream ss(line);
        Proxy proxy;
        std::string login_pass, ip_port;
 
        // separate login:pass and ip:port
        if (std::getline(ss, login_pass, '@') && std::getline(ss, ip_port)) {
            // separete login and pass
            std::stringstream login_pass_ss(login_pass);
            if (std::getline(login_pass_ss, proxy.login, ':') && std::getline(login_pass_ss, proxy.password)) {
                // separate ip and port
                std::stringstream ip_port_ss(ip_port);
                if (std::getline(ip_port_ss, proxy.IP, ':') && std::getline(ip_port_ss, proxy.port)) {
                    proxies.push_back(proxy);
                }
            }
        }
    }

    in.close();

    // random proxy selection
    if (!proxies.empty()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, proxies.size() - 1);
        std::cout << "\n\n\nIP: " << proxies[dis(gen)].IP << std::endl;
        std::cout << "port: " << proxies[dis(gen)].port << std::endl;
        std::cout << "login: " << proxies[dis(gen)].login << std::endl;
        std::cout << "password: " << proxies[dis(gen)].password << std::endl << std::endl << std::endl;
        return proxies[dis(gen)];
    }

    return Proxy(); // return empty proxy if the proxies list is empty
}

// Base64 encoding
std::string encode_base64(const std::string& input) {
    std::string output;
    output.resize(boost::beast::detail::base64::encoded_size(input.size()));
    boost::beast::detail::base64::encode(
        const_cast<char*>(output.data()),  // casting to void*
        input.data(),
        input.size()
    );
    return output;
}

// Base64 decoding
std::string decode_base64(const std::string& input) {
    std::string output;
    output.resize(boost::beast::detail::base64::decoded_size(input.size()));
    auto result = boost::beast::detail::base64::decode(
        const_cast<char*>(output.data()),  // casting to void*
        input.data(),
        input.size()
    );
    output.resize(result.first);  // resize data after decoding
    return output;
}

// Function for data relay between client and server
void relay_data(std::shared_ptr<tcp::socket> src, std::shared_ptr<tcp::socket> dst);

// Function to handle incoming client connections
void handle_client(std::shared_ptr<tcp::socket> client_socket, io_context& io_context) {
    Proxy proxy = get_proxy();
    std::vector<char> buffer(8192);
    boost::system::error_code ec;
    size_t bytes_read = client_socket->read_some(boost::asio::buffer(buffer), ec);

    if (ec) {
        std::cerr << "Request read error: " << ec.message() << std::endl;
        return;
    }

    std::string request(buffer.data(), bytes_read);
    std::cout << "Received request:\n" << request << std::endl;

    if (request.find("CONNECT") != 0) {
        std::cerr << "Only CONNECT method is supported!\n";
        return;
    }

    // Check for Proxy-Authorization header
    size_t auth_pos = request.find("Proxy-Authorization: Basic ");
    if (auth_pos == std::string::npos) {
        std::string auth_response = 
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            "Proxy-Authenticate: Basic realm=\"Secure Proxy\"\r\n\r\n";
        boost::asio::write(*client_socket, boost::asio::buffer(auth_response), ec);
        return;
    }

    size_t auth_start = auth_pos + 27;
    size_t auth_end = request.find("\r\n", auth_start);
    std::string encoded_credentials = request.substr(auth_start, auth_end - auth_start);
    std::string decoded_credentials = decode_base64(encoded_credentials);

    size_t separator_pos = decoded_credentials.find(':');
    if (separator_pos == std::string::npos) {
        std::cerr << "Invalid authentication format!" << std::endl;
        return;
    }

    std::string username = decoded_credentials.substr(0, separator_pos);
    std::string password = decoded_credentials.substr(separator_pos + 1);

    if (username != proxy.login || password != proxy.password) {
        std::cerr << "Invalid username/password!\n";
        std::string auth_fail_response = 
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            "Proxy-Authenticate: Basic realm=\"Secure Proxy\"\r\n\r\n";
        boost::asio::write(*client_socket, boost::asio::buffer(auth_fail_response), ec);
        return;
    }

    // Extract target host and port
    size_t host_start = request.find(' ') + 1;
    size_t host_end = request.find(' ', host_start);
    std::string target_host = request.substr(host_start, host_end - host_start);
    // std::cout << "Target server: " << target_host << std::endl;

    // Use resolver to connect to the proxy
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(proxy.IP, proxy.port);

    std::shared_ptr<tcp::socket> proxy_socket = std::make_shared<tcp::socket>(io_context);
    boost::asio::connect(*proxy_socket, endpoints);

    // Send CONNECT request to the proxy
    std::string auth = "Proxy-Authorization: Basic " + encode_base64(proxy.login + ":" + proxy.password) + "\r\n";
    std::string connect_request = "CONNECT " + target_host + " HTTP/1.1\r\n"
                                    "Host: " + target_host + "\r\n"
                                    "Proxy-Connection: keep-alive\r\n"
                                    "Connection: keep-alive\r\n"
                                    + auth + "\r\n";

    boost::asio::write(*proxy_socket, boost::asio::buffer(connect_request), ec);

    // Read proxy response
    bytes_read = proxy_socket->read_some(boost::asio::buffer(buffer), ec);
    if (ec) {
        std::cerr << "Error receiving response from proxy: " << ec.message() << std::endl;
        return;
    }

    std::string proxy_response(buffer.data(), bytes_read);
    if (proxy_response.find("200 Connection established") == std::string::npos) {
        std::cerr << "Failed to establish connection through proxy!\n";
        return;
    }

    // Send success response to client
    std::string success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    boost::asio::write(*client_socket, boost::asio::buffer(success_response), ec);

    // Start threads for bidirectional data transfer
    std::thread(relay_data, client_socket, proxy_socket).detach();
    relay_data(proxy_socket, client_socket);
}

void relay_data(std::shared_ptr<tcp::socket> src, std::shared_ptr<tcp::socket> dst) {
    try {
        mutex.lock();
        std::cout << "Relay_data вызван\n";
        std::vector<char> data(1024);
        while (src->is_open() && dst->is_open()) {
            boost::system::error_code error;
            size_t len = src->read_some(buffer(data), error);

            if (error == boost::asio::error::eof) {
                std::cerr << "Connection closed by remote host: " << error.message() << std::endl;
                if (src->is_open()) {
                    src->shutdown(tcp::socket::shutdown_both);
                    src->close();
                }
                if (dst->is_open()) {
                    dst->shutdown(tcp::socket::shutdown_both);
                    dst->close();
                }
                break;
            }
            else if (error) {
                std::cerr << "Read error: " << error.message() << std::endl;
                break;
            }

            boost::asio::write(*dst, buffer(data.data(), len), error);
            if (error) {
                std::cerr << "Write error: " << error.message() << std::endl;
                break;
            }
        }

        // Close socket
        if (src->is_open()) {
            src->shutdown(tcp::socket::shutdown_both);
            src->close();
        }
        if (dst->is_open()) {
            dst->shutdown(tcp::socket::shutdown_both);
            dst->close();
        }
        
        mutex.unlock();

    } catch (const std::exception &e) {
        std::cerr << "Error while transferring data: " << e.what() << std::endl;
    }
}

int main() {
    int port = 8080;
    io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

    std::cout << "Server is running on " << port << " port...\n";

    const int thread_pool_size = 4;
    std::vector<std::thread> thread_pool;

    for (int i = 0; i < thread_pool_size; ++i) {
        thread_pool.emplace_back([&io_context]() {
            io_context.run();
        });
    }

    while (true) {
        std::shared_ptr<tcp::socket> client_socket = std::make_shared<tcp::socket>(io_context);
        acceptor.accept(*client_socket);

        std::thread([client_socket, &io_context]() {
            handle_client(client_socket, io_context);
        }).detach();
    }

    for (auto& t : thread_pool) {
        t.join();
    }

    return 0;
}
