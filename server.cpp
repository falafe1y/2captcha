#include <iostream>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <thread>

using namespace boost::asio;
using ip::tcp;

const std::string PROXY_IP = "118.193.58.115";
const std::string PROXY_PORT = "2333";
const std::string PROXY_USER = "u54ea530557a605db-zone-custom-region-eu";
const std::string PROXY_PASS = "u54ea530557a605db";

// encode in Base64
std::string encode_base64(const std::string& input) {
    std::string output(boost::beast::detail::base64::encoded_size(input.size()), '\0');
    boost::beast::detail::base64::encode(const_cast<char*>(output.data()), input.data(), input.size());
    return output;
}

std::string decode_base64(const std::string& input) {
    std::string output(boost::beast::detail::base64::decoded_size(input.size()), '\0');
    auto result = boost::beast::detail::base64::decode(const_cast<char*>(output.data()), input.data(), input.size());
    output.resize(result.first); // correcting size of output dataz
    return output;
}

// handle proxied connection
void relay_data(std::shared_ptr<tcp::socket> src, std::shared_ptr<tcp::socket> dst) {
    try {
        boost::array<char, 8192> data;
        while (src->is_open() && dst->is_open()) {
            boost::system::error_code error;
            size_t len = src->read_some(buffer(data), error);

            if (error) {
                std::cerr << "Read error: " << error.message() << std::endl;
                break;
            }

            if (!dst->is_open()) {
                std::cerr << "Destination socket closed, stopping transfer." << std::endl;
                break;
            }

            boost::asio::write(*dst, buffer(data.data(), len), error);
            if (error) {
                std::cerr << "Write error: " << error.message() << std::endl;
                break;
            }
        }
    } catch (std::exception &e) {
        std::cerr << "Error while transferring data: " << e.what() << std::endl;
    }
}

// handle HTTPS CONNECT
void handle_client(std::shared_ptr<tcp::socket> client_socket, io_context& io_context) {
    try {
        boost::array<char, 1024> buffer;
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

        // check for Proxy-Authorization header
        size_t auth_pos = request.find("Proxy-Authorization: Basic ");
        if (auth_pos == std::string::npos) {
            // if no authorization, send 407 Proxy Authentication Required
            std::string auth_response = 
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"Secure Proxy\"\r\n\r\n";
            boost::asio::write(*client_socket, boost::asio::buffer(auth_response), ec);
            return;
        }

        // extract and decode login/password
        size_t auth_start = auth_pos + 27;  // length of "Proxy-Authorization: Basic " = 27
        size_t auth_end = request.find("\r\n", auth_start);
        std::string encoded_credentials = request.substr(auth_start, auth_end - auth_start);
        std::string decoded_credentials = decode_base64(encoded_credentials);

        std::cout << "Decoded credentials: |" << decoded_credentials << '|' << std::endl;

        // parse "username:password"
        size_t separator_pos = decoded_credentials.find(':');
        if (separator_pos == std::string::npos) {
            std::cerr << "Invalid authentication format!" << std::endl;
            return;
        }
        std::string username = decoded_credentials.substr(0, separator_pos);
        std::string password = decoded_credentials.substr(separator_pos + 1);

        std::cout << "Username: " << username << ", Password: " << password << std::endl;

        // check credentials (can be replaced with a database)
        if (username != PROXY_USER || password != PROXY_PASS) {
            std::cerr << "Invalid username/password!\n";
            std::string auth_fail_response = 
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"Secure Proxy\"\r\n\r\n";
            boost::asio::write(*client_socket, boost::asio::buffer(auth_fail_response), ec);
            return;
        }

        std::cout << "User authenticated: " << username << std::endl;

        // extract target host and port
        size_t host_start = request.find(' ') + 1;
        size_t host_end = request.find(' ', host_start);
        std::string target_host = request.substr(host_start, host_end - host_start);
        std::cout << "Target server: " << target_host << std::endl;

        // connect to external proxy
        std::shared_ptr<tcp::socket> proxy_socket = std::make_shared<tcp::socket>(io_context);
        proxy_socket->connect(tcp::endpoint(boost::asio::ip::make_address(PROXY_IP), std::stoi(PROXY_PORT)));

        // send CONNECT request to external proxy
        std::string auth = "Proxy-Authorization: Basic " + encode_base64(PROXY_USER + ":" + PROXY_PASS) + "\r\n";
        std::string connect_request = "CONNECT " + target_host + " HTTP/1.1\r\n"
                                        "Host: " + target_host + "\r\n"
                                        "Proxy-Connection: keep-alive\r\n"
                                        "Connection: keep-alive\r\n"
                                        + auth + "\r\n";

        std::cout << "Proxy authorization header: " << auth << std::endl;

        boost::asio::write(*proxy_socket, boost::asio::buffer(connect_request), ec);
        if (ec) {
            std::cerr << "Error sending request to proxy: " << ec.message() << std::endl;
            return;
        }

        // response from proxy
        bytes_read = proxy_socket->read_some(boost::asio::buffer(buffer), ec);
        if (ec) {
            std::cerr << "Error receiving response from proxy: " << ec.message() << std::endl;
            return;
        }

        std::string proxy_response(buffer.data(), bytes_read);
        std::cout << "Proxy response:\n" << proxy_response << std::endl;

        if (proxy_response.find("200 Connection established") == std::string::npos) {
            std::cerr << "Failed to establish connection through proxy!\n";
            return;
        }

        // inform the client that the connection has been established
        std::string success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        boost::asio::write(*client_socket, boost::asio::buffer(success_response), ec);
        if (ec) {
            std::cerr << "Error sending response to client: " << ec.message() << std::endl;
            return;
        }

        // start data transfer threads
        std::thread(relay_data, client_socket, proxy_socket).detach();
        relay_data(proxy_socket, client_socket);

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    try {
        io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));

        std::cout << "Proxy server started on port 8080..." << std::endl;

        while (true) {
            std::shared_ptr<tcp::socket> client_socket = std::make_shared<tcp::socket>(io_context);
            acceptor.accept(*client_socket);
            std::thread(handle_client, client_socket, std::ref(io_context)).detach();
        }

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
