#include <thread>
#include <vector>
#include <random>
#include <format>
#include <sstream>
#include <fstream>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
 
using namespace boost::asio;
using ip::tcp;

struct Proxy {
    std::string IP;
    std::string port;
    std::string login;
    std::string password;
};

Proxy global_proxy;

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
        std::cout << "Use proxy with IP: " << proxies[dis(gen)].IP << std::endl;    // debug info
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

double get_tcp_handshake_rtt(std::shared_ptr<tcp::socket>& socket) {
    struct tcp_info info;
    socklen_t len = sizeof(info);

    if (getsockopt(socket->native_handle(), SOL_TCP, TCP_INFO, &info, &len) == 0) {
        return info.tcpi_rtt / 1000.0; // milliseconds
    }
    return -1.0;
}

// Data relay between client and server
void relay_data(std::shared_ptr<tcp::socket> src, std::shared_ptr<tcp::socket> dst) {
    try {
        std::vector<char> data(4096);
        while (src->is_open() && dst->is_open()) {
            boost::system::error_code error;
            size_t len = src->read_some(boost::asio::buffer(data), error);

            if (error == boost::asio::error::eof) {
                std::cerr << "[INFO] Connection closed by remote host" << std::endl;
                break;
            } else if (error) {
                std::cerr << "[ERROR] Read error (" << error.value() << "): " << error.message() << std::endl;
                break;
            }

            if (dst->is_open()) {
                boost::asio::write(*dst, boost::asio::buffer(data.data(), len), error);
                if (error) {
                    std::cerr << "[ERROR] Write error (" << error.value() << "): " << error.message() << std::endl;
                    break;
                }
            } else {
                std::cerr << "[WARNING] Destination socket is closed, skipping write" << std::endl;
                break;
            }
        }
        
        // lambda func for close connection
        auto safe_close = [](std::shared_ptr<tcp::socket> sock, const std::string &name) {
            if (sock->is_open()) {
                boost::system::error_code ec;
                sock->shutdown(tcp::socket::shutdown_both, ec);
                if (ec) {
                    std::cerr << "[WARNING] Failed to shutdown " << name << ": " << ec.message() << std::endl;
                }
                sock->close(ec);
                if (ec) {
                    std::cerr << "[WARNING] Failed to close " << name << ": " << ec.message() << std::endl;
                } else {
                    std::cout << "[INFO] " << name << " closed" << std::endl;
                }
            }
        };

        safe_close(src, "Src");
        safe_close(dst, "Dst");

    } catch (const std::exception &e) {
        std::cerr << "[FATAL] Exception in relay_data: " << e.what() << std::endl;
    }
}

// Handle incoming client connections
void handle_client(std::shared_ptr<tcp::socket> client_socket, io_context& io_context) {
    std::vector<char> buffer(4096);
    boost::system::error_code ec;
    size_t bytes_read = client_socket->read_some(boost::asio::buffer(buffer), ec);

    if (ec) {
        std::cerr << "[WARNING] Request read error: " << ec.message() << std::endl;
        return;
    }

    std::string request(buffer.data(), bytes_read);

    // check for Proxy-Authorization header
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
        std::cerr << "[ERROR] Invalid authentication format!" << std::endl;
        return;
    }

    std::string username = decoded_credentials.substr(0, separator_pos);
    std::string password = decoded_credentials.substr(separator_pos + 1);

    if (username != global_proxy.login || password != global_proxy.password) {
        std::cerr << "[ERROR] Invalid username/password!" << std::endl;
        std::string auth_fail_response = 
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            "Proxy-Authenticate: Basic realm=\"Secure Proxy\"\r\n\r\n";
        boost::asio::write(*client_socket, boost::asio::buffer(auth_fail_response), ec);
        return;
    }

    // extract target host and port
    size_t host_start = request.find(' ') + 1;
    size_t host_end = request.find(' ', host_start);
    std::string target_host = request.substr(host_start, host_end - host_start);
    std::cout << "[HOST] Host: " << target_host << std::endl;

    // use resolver to connect to the proxy
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(global_proxy.IP, global_proxy.port);

    std::shared_ptr<tcp::socket> proxy_socket = std::make_shared<tcp::socket>(io_context);
    boost::asio::connect(*proxy_socket, endpoints);
    std::cout << "\n[SPEED] Connection speed to proxy: " << get_tcp_handshake_rtt(proxy_socket) << " ms\t";

    // send CONNECT request to the proxy
    std::string auth = "Proxy-Authorization: Basic " + encode_base64(global_proxy.login + ":" + global_proxy.password) + "\r\n";
    std::string connect_request = "CONNECT " + target_host + " HTTP/1.1\r\n"
                                    "Host: " + target_host + "\r\n"
                                    "Proxy-Connection: keep-alive\r\n"
                                    "Connection: keep-alive\r\n"
                                    + auth + "\r\n";

    boost::asio::write(*proxy_socket, boost::asio::buffer(connect_request), ec);

    // read proxy response
    bytes_read = proxy_socket->read_some(boost::asio::buffer(buffer), ec);
    if (ec) {
        std::cerr << "[ERROR] Error receiving response from proxy: " << ec.message() << std::endl;
        return;
    }

    std::string proxy_response(buffer.data(), bytes_read);
    if (proxy_response.find("200 Connection established") == std::string::npos) {
        std::cerr << "[ERROR] Failed to establish connection through proxy!" << std::endl;
        return;
    }

    // send success response to client
    std::string success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    boost::asio::write(*client_socket, boost::asio::buffer(success_response), ec);

    // start threads for bidirectional data transfer
    std::thread(relay_data, client_socket, proxy_socket).detach();
    relay_data(proxy_socket, client_socket);
}

int main(int argc, char *argv[]) {
    int port = std::stoi(argv[1]);

    io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
    global_proxy = get_proxy();

    std::cout << "Server is running on " << port << " port..." << std::endl << std::endl;

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
