#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/array.hpp>
#include <thread>

using namespace boost::asio;
using ip::tcp;

const std::string PROXY_IP = "118.193.58.115";
const std::string PROXY_PORT = "2333";
const std::string PROXY_USER = "u54ea530557a605db-zone-custom-region-eu";
const std::string PROXY_PASS = "u54ea530557a605db";

// encoding login and password in Base64
std::string encode_base64(const std::string& input) {
    static const char* b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    while (output.size() % 4) output.push_back('=');
    return output;
}

// handle HTTPS CONNECT
void handle_client(tcp::socket client_socket, io_context& io_context) {
    try {
        boost::array<char, 1024> buffer;
        boost::system::error_code ec;
        size_t bytes_read = client_socket.read_some(boost::asio::buffer(buffer), ec);

        std::string request(buffer.data(), bytes_read);
        std::cout << "Received request:\n" << request << std::endl;

        if (request.find("CONNECT") != 0) {
            std::cerr << "Only CONNECT method is supported!\n";
            return;
        }

        // extract the target server and port
        size_t host_start = request.find(' ') + 1;
        size_t host_end = request.find(' ', host_start);
        std::string target_host = request.substr(host_start, host_end - host_start);
        std::cout << "Target host: " << target_host << std::endl;

        // connect to external proxy
        tcp::socket proxy_socket(io_context);
        proxy_socket.connect(tcp::endpoint(boost::asio::ip::make_address(PROXY_IP), std::stoi(PROXY_PORT)));

        // request with proxy
        std::string auth = "Proxy-Authorization: Basic " + encode_base64(PROXY_USER + ":" + PROXY_PASS) + "\r\n";
        std::string connect_request = "CONNECT " + target_host + " HTTP/1.1\r\n" + auth + "\r\n";

        try {
            proxy_socket.send(boost::asio::buffer(connect_request));
        } catch (const boost::system::system_error& e) {
            std::cerr << "Exception: " << e.what() << std::endl;
        }

        // response from external proxy
        bytes_read = proxy_socket.read_some(boost::asio::buffer(buffer));
        std::string proxy_response(buffer.data(), bytes_read);
        std::cout << "Proxy response:\n" << proxy_response << std::endl;

        if (proxy_response.find("200 Connection established") == std::string::npos) {
            std::cerr << "Failed to establish connection via proxy!\n";
            return;
        }

        // response that the connection is established
        std::string success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        client_socket.send(boost::asio::buffer(success_response));

        // forward traffic between the client and the external proxy
        std::thread([&] {
            boost::array<char, 8192> data;
            while (true) {
                boost::system::error_code error;
                size_t len = client_socket.read_some(boost::asio::buffer(data), error);
                if (error) break;
                proxy_socket.send(boost::asio::buffer(data.data(), len));
            }
        }).detach();

        boost::array<char, 8192> data;
        while (true) {
            boost::system::error_code error;
            size_t len = proxy_socket.read_some(boost::asio::buffer(data), error);
            if (error) break;
            client_socket.send(boost::asio::buffer(data.data(), len));
        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

int main() {
    try {
        io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));

        std::cout << "Proxy server started on port 8080..." << std::endl;

        while (true) {
            tcp::socket client_socket(io_context);
            acceptor.accept(client_socket);
            std::thread(handle_client, std::move(client_socket), std::ref(io_context)).detach();
        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
