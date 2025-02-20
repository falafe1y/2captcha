#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

void send_request(const std::string& server_address, int port, const std::string& login, const std::string& password, const std::string& url) {
    boost::asio::io_context io_context;
    tcp::resolver resolver(io_context);

    std::string str_port = std::to_string(port);
    tcp::resolver::results_type endpoints = resolver.resolve(server_address, str_port);

    tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    // Request string "login + password + url"
    std::string request = login + " " + password + " " + url;
    
    boost::asio::write(socket, boost::asio::buffer(request));

    // Response
    try {
        char response[4096];
        size_t length = socket.read_some(boost::asio::buffer(response));
        std::cout << "Response from the server:\n\n" << std::string(response, length) << "\n\n";
    } catch (const boost::system::system_error& e) {
        std::cerr << "Error reading data: " << e.what() << std::endl;
    }

    socket.close();
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <login> <password> <URL>\n";
        return 1;
    }

    std::string server_address = "127.0.0.1";  
    int server_port = 8080;
    std::string login = argv[1];
    std::string password = argv[2];
    std::string url = argv[3];

    send_request(server_address, server_port, login, password, url);
    return 0;
}

