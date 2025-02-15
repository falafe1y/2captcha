#include <iostream>
#include <string>
#include <curl/curl.h>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

const std::string proxy_address = "44.219.175.186";  // Proxy address
const int proxy_port = 80;  // Proxy port

// Function for handling request through proxy using libcurl
size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

std::string handle_request(const std::string &url) {
    CURL *curl;
    CURLcode res;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy_address.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxy_port);
        
        // Set up a callback to write data to a string
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
            std::cout << "Request from the client: " << client_request << "\n";

            // Processing request via proxy
            std::string response = handle_request(url);

            std::cout << "Response from proxy:\n\n" << response << std::endl;

            // Sending a response to the client
            boost::asio::write(socket, boost::asio::buffer(response));

            socket.close();
        } catch (const std::exception& e) {
            std::cerr << "Error processing request: " << e.what() << std::endl;
        }
    }
}

int main() {
    const int port = 8080;
    start_server(port, "http://example.com");
    return 0;
}
