#ifndef CRYPTO_CONNECTION_HANDLER_H
#define CRYPTO_CONNECTION_HANDLER_H

#include "ConnectionManager.h"
#include "RegReconnect.h"
#include "RSAKey.h"
#include "cksum_new.h"
#include <fstream>
#include <iostream>
#include <queue.h>
#include <rsa.h>
#include "Response.h"
#include <filesystem>
#include "Constants.h"

/**
 * @class CryptoConnectionHandler
 * @brief Provides cryptographic handling of connections, including key management, encryption, decryption, and CRC validation.
 */
class CryptoConnectionHandler {
public:
    /**
     * @brief Retrieves the size of the public RSA key.
     *
     * @param publicKey The public key of type CryptoPP::RSA::PublicKey.
     * @return The size of the public key in bytes.
     */
    static size_t GetPublicKeySize(const CryptoPP::RSA::PublicKey& publicKey);

    /**
     * @brief Decrypts an AES key from the received payload using a private RSA key.
     *
     * @param bufferReceiveData The data buffer received from the server.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param privateKey The RSA private key used for decryption.
     * @return A vector of uint8_t representing the decrypted AES key.
     */
    static std::vector<uint8_t> decryptAESKeyFromPayload(const std::vector<uint8_t>& bufferReceiveData, const std::vector<uint8_t>& bufferUuid, CryptoPP::RSA::PrivateKey& privateKey);

    /**
     * @brief Extracts the CRC value sent from the server.
     *
     * @param bufferReceiveData The data buffer containing the server's response.
     * @return The CRC value extracted as an integer.
     */
    static int extractCrcServer(const std::vector<uint8_t>& bufferReceiveData);

    /**
     * @brief Sends a CRC validation request to the server.
     *
     * @param connection The connection manager instance handling the connection.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param code The request code indicating the type of CRC validation.
     * @param encryptedFileNameBytes The encrypted file name in binary form.
     */
    static void sendCRCValidationRequest(ConnectionManager& connection, const std::vector<uint8_t>& bufferUuid, int code, const std::vector<uint8_t>& encryptedFileNameBytes);

    /**
     * @brief Handles the server's response to a CRC validation request.
     *
     * @param connection The connection manager instance handling the connection.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param encryptedFileNameBytes The encrypted file name in binary form.
     * @param crcClient The CRC calculated on the client side.
     * @param filesize The size of the file being transferred.
     * @param filePath The path to the file being transferred.
     * @return True if the server response indicates success, false otherwise.
     */
    static bool handleServerResponse(ConnectionManager& connection, const std::vector<uint8_t>& bufferUuid, const std::vector<uint8_t>& encryptedFileNameBytes, int crcClient, uintmax_t filesize, std::string filePath);

    /**
     * @brief Performs a CRC check for the transferred file.
     *
     * @param connection The connection manager instance handling the connection.
     * @param filePath The path to the file to be checked.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param filesize The size of the file being transferred.
     */
    static void crcCheck(ConnectionManager& connection, const std::string& filePath, const std::vector<uint8_t>& bufferUuid, uintmax_t filesize);

    /**
     * @brief Receives an AES key from the server with retry attempts if necessary.
     *
     * @param connection The connection manager instance handling the connection.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param privateKey The RSA private key used for decrypting the received AES key.
     * @param clientName The name of the client.
     * @param publicKeyDER The client's public key in DER format.
     * @return A vector of uint8_t containing the decrypted AES key.
     */
    static std::vector<uint8_t> receiveAESKeyWithRetries(ConnectionManager& connection, const std::vector<uint8_t>& bufferUuid, CryptoPP::RSA::PrivateKey& privateKey, const std::string& clientName, std::vector<uint8_t> publicKeyDER);

    /**
     * @brief Attempts to reconnect and receive an AES key from the server.
     *
     * @param connection The connection manager instance handling the connection.
     * @param bufferUuid The unique identifier buffer for the client.
     * @param privateKey The RSA private key used for decryption.
     * @param clientName The name of the client.
     * @param publicKey The public key for reconnection.
     * @return A vector of uint8_t containing the decrypted AES key.
     */
    static std::vector<uint8_t> reconnectAndReceiveAESKey(ConnectionManager& connection, std::vector<uint8_t>& bufferUuid, CryptoPP::RSA::PrivateKey& privateKey, std::string clientName, CryptoPP::RSA::PublicKey& publicKey);

    /**
     * @brief Generates an RSA public key and sends it to the server.
     *
     * @param clientName The name of the client.
     * @param connection The connection manager instance handling the connection.
     * @param bufferReceiveData Data buffer for any received data.
     * @param publicKey The RSA public key generated for the client.
     * @param privateKey The RSA private key generated for the client.
     * @param decryptedAESKey A vector to store the decrypted AES key after receiving it from the server.
     */
    static void generateAndSendPublicKey(const std::string& clientName, ConnectionManager& connection, const std::vector<uint8_t>& bufferReceiveData, CryptoPP::RSA::PublicKey& publicKey, CryptoPP::RSA::PrivateKey& privateKey, std::vector<uint8_t>& decryptedAESKey);
};

#endif // CRYPTO_CONNECTION_HANDLER_H
