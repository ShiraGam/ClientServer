#ifndef REG_RECONNECT_H
#define REG_RECONNECT_H

#include <cstring>      // for memcpy
#include <algorithm>    // for std::min
#include <stdexcept>    // for std::runtime_error
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include "Request.h"
#include "Constants.h"
#include "Response.h"

class ConnectionManager;

/**
 * @class RegReconnect
 * @brief Handles client registration, reconnection, and file chunking for transmission.
 */
class RegReconnect {
public:
    /**
     * @brief Constructor: Initializes the registration and reconnection handler.
     */
    RegReconnect();

    /**
     * @brief Destructor: Cleans up any resources used by the handler.
     */
    ~RegReconnect();

    /**
     * @brief Reads transfer information (IP, port, client name, and file path) from a configuration file.
     *
     * @param ip Reference to store the server IP address.
     * @param port Reference to store the server port.
     * @param clientName Reference to store the client's name.
     * @param filePath Reference to store the file path to be transferred.
     * @return True if the file was read successfully; false otherwise.
     */
    bool readFromTransfer(std::string& ip, std::string& port, std::string& clientName, std::string& filePath);

    /**
     * @brief Encrypts and returns the filename for secure transmission.
     *
     * @param fileName The original file name.
     * @return A string representing the encrypted file name.
     */
    static std::string getEncryptedFileName(const std::string& fileName);

    /**
     * @brief Creates the payload for sending a public key (request code 826).
     *
     * @param name The client's name.
     * @param publicKey The public key in binary format.
     * @return A vector of uint8_t containing the prepared payload.
     */
    static std::vector<uint8_t> createPayloadForRequest826(const std::string& name, const std::vector<uint8_t>& publicKey);

    /**
     * @brief Builds a payload for file transfer, including file metadata and content.
     *
     * @param contentSize The size of the content being sent.
     * @param origFileSize The original file size before encryption.
     * @param packetNumber The current packet number in the transfer.
     * @param totalPackets The total number of packets in the transfer.
     * @param fileName The name of the file being sent.
     * @param messageContent The encrypted file content.
     * @param clientId The unique client identifier.
     * @return A vector of uint8_t containing the constructed payload.
     */
    static std::vector<uint8_t> buildPayload(
        uint32_t contentSize,
        uintmax_t origFileSize,
        uint16_t packetNumber,
        uint16_t totalPackets,
        const std::string& fileName,
        const std::vector<uint8_t>& messageContent,
        const std::vector<uint8_t>& clientId
    );

    /**
     * @brief Splits an encrypted file into chunks and sends each chunk as a payload to the server.
     *
     * @param origFileSize The original file size before encryption.
     * @param encryptedFileName The name of the encrypted file.
     * @param fileName The name of the original file.
     * @param clientId The unique client identifier.
     * @param connection The connection manager instance handling the connection.
     */
    static void sendEncryptedFileInChunks(
        uintmax_t origFileSize,
        const std::string& encryptedFileName,
        const std::string& fileName,
        const std::vector<uint8_t>& clientId,
        ConnectionManager& connection
    );

    /**
     * @brief Registers the client with the server or re-establishes a connection if already registered.
     *
     * @param connection The connection manager instance handling the connection.
     * @param registration Reference to a RegReconnect instance for registration handling.
     * @param ip The server IP address.
     * @param port The server port.
     * @param clientName The client's name.
     * @param filePath The file path to be transferred.
     * @return True if registration was successful, false otherwise.
     */
    bool performRegistration(ConnectionManager& connection, RegReconnect& registration, std::string& ip, std::string& port, std::string& clientName, std::string& filePath);

    /**
     * @brief Sends a registration request to the server with the client's name.
     *
     * @param connection The connection manager instance handling the connection.
     * @param clientName The name of the client.
     * @param bufferReceiveData Buffer to store data received in response.
     * @param bufferUuid Buffer to store the unique client identifier received upon registration.
     * @return True if registration request was sent successfully, false otherwise.
     */
    bool sendRegisterRequest(ConnectionManager& connection, const std::string& clientName, std::vector<uint8_t>& bufferReceiveData, std::vector<uint8_t>& bufferUuid);

    /**
     * @brief Reads the client’s unique identifier (UUID) from a file.
     *
     * @return A vector of uint8_t containing the UUID read from the file.
     */
    static std::vector<uint8_t> readUuidFromFile();
};

#endif // REG_RECONNECT_H
