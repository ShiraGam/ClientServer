#ifndef RESPONSE_H
#define RESPONSE_H

#include <cstdint>
#include <vector>
#include "response.h"
#include <stdexcept>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include "Constants.h"
#include "ConnectionManager.h"

/**
 * @class Response
 * @brief Provides utilities for handling and extracting information from server responses.
 */
class Response {
public:
    /**
     * @brief Extracts the version from the response buffer.
     *
     * @param buffer The response buffer containing the version field.
     * @return The version as a uint8_t.
     */
    static uint8_t extractVersion(const std::vector<uint8_t>& buffer);

    /**
     * @brief Extracts the response code from the buffer.
     *
     * @param buffer The response buffer containing the code field.
     * @return The response code as a uint16_t.
     */
    static uint16_t extractCode(const std::vector<uint8_t>& buffer);

    /**
     * @brief Extracts the payload size from the buffer.
     *
     * @param buffer The response buffer containing the payload size field.
     * @return The size of the payload as a uint32_t.
     */
    static uint32_t extractPayloadSize(const std::vector<uint8_t>& buffer);

    /**
     * @brief Extracts the payload data from the response buffer.
     *
     * @param buffer The response buffer containing the payload.
     * @param reply_length The total length of the received reply.
     * @param payload_size The expected size of the payload.
     * @return A vector of uint8_t containing the extracted payload data.
     * @throws std::runtime_error if the payload size is incorrect.
     */
    static std::vector<uint8_t> extractPayload(const std::vector<uint8_t>& buffer, size_t reply_length, uint32_t payload_size);

    /**
     * @brief Receives and processes a registration request from the server.
     *
     * @param clientName The name of the client registering.
     * @param buffer The buffer containing the response data.
     * @param bufferUuid A buffer to store the client's unique identifier (UUID) upon registration.
     * @return True if the registration request was successfully processed; false otherwise.
     */
    static bool recvRegisterRequest(const std::string& clientName, const std::vector<uint8_t>& buffer, std::vector<uint8_t>& bufferUuid);
};

#endif // RESPONSE_H
