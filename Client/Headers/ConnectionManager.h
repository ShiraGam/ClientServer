#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <boost/endian/conversion.hpp>
#include "RegReconnect.h"
#include "Request.h"
#include "Response.h"

/**
 * @class ConnectionManager
 * @brief Manages the connection between the client and server, handling data transmission over TCP.
 */
class ConnectionManager {
public:
    /**
     * @brief Constructor: Initializes the TCP socket using Boost.Asio's io_context.
     * Creates an io_context and a socket that will be used for managing
     * connection and data transfers with the server.
     */
    ConnectionManager();

    /**
     * @brief Destructor: Closes the connection if it is still open.
     * Ensures any open connection is safely closed upon object destruction.
     */
    ~ConnectionManager();

    /**
     * @brief Connects to the server with a specified IP address and port.
     *
     * @param ip The IP address of the server as a string.
     * @param port The port number to connect to, given as a string.
     * @throws boost::system::system_error if the connection fails.
     */
    void connectToServer(const std::string& ip, const std::string& port);

    /**
     * @brief Sends binary data to the server.
     *
     * @param data A vector of uint8_t containing the binary data to send.
     * @throws boost::system::system_error if sending data fails.
     */
    void sendData(const std::vector<uint8_t>& data);

    /**
     * @brief Receives binary data from the server.
     *
     * @return A vector of uint8_t containing the received binary data.
     * @throws boost::system::system_error if receiving data fails.
     */
    std::vector<uint8_t> receiveData();

    /**
     * @brief Closes the connection with the server.
     * Terminates the connection by shutting down and closing the socket.
     */
    void closeConnection();

private:
    boost::asio::io_context io_context;  ///< Boost.Asio context that handles IO events.
    boost::asio::ip::tcp::socket socket; ///< The TCP socket used for the connection.
};

#endif // CONNECTION_MANAGER_H

