#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

void send_request(const std::string& server_address, int port, const std::string& request) {
    boost::asio::io_context io_context;
    tcp::resolver resolver(io_context);

    std::string str_port = std::to_string(port);
    tcp::resolver::results_type endpoints = resolver.resolve(server_address, str_port);

    tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    // Sending a request to the server
    boost::asio::write(socket, boost::asio::buffer(request));

    // Get response
    try {
        char response[2048];
        size_t length = socket.read_some(boost::asio::buffer(response));
        std::cout << "Response from the server: " << std::string(response, length) << std::endl;
    } catch (const boost::system::system_error& e) {
        std::cerr << "Error reading data: " << e.what() << std::endl;
    }

    socket.close();
}

int main() {
    std::string server_address = "127.0.0.1";   // Server address
    int server_port = 8080;     // Server port
    std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"; // Request

    send_request(server_address, server_port, request);

    return 0;
}
