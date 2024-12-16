#ifndef REQUEST_H
#define REQUEST_H

#include <cstdint>
#include <vector>
#include <cstring> // For memcpy
#include <iomanip>
#include <stdexcept> // For throwing exceptions

/**
 * @class Request
 * @brief Represents a network request with a header and a payload for communication.
 */
class Request {
public:
    /**
     * @brief Default Constructor: Initializes an empty request.
     */
    Request();

    /**
     * @brief Parameterized Constructor: Initializes a request with given details.
     *
     * @param clientId The unique client identifier (16 bytes).
     * @param version The version number of the client protocol (1 byte).
     * @param code The request code indicating the type of request (2 bytes).
     * @param payload The request payload in binary format.
     */
    Request(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload);

    /**
     * @brief Retrieves the client ID associated with the request.
     *
     * @return A reference to the vector of uint8_t representing the client ID.
     */
    const std::vector<uint8_t>& getClientId() const;

    /**
     * @brief Retrieves the version of the client protocol.
     *
     * @return The version number as a uint8_t.
     */
    uint8_t getVersion() const;

    /**
     * @brief Retrieves the request code indicating the type of request.
     *
     * @return The request code as a uint16_t.
     */
    uint16_t getCode() const;

    /**
     * @brief Retrieves the size of the payload in bytes.
     *
     * @return The payload size as a uint32_t.
     */
    uint32_t getPayloadSize() const;

    /**
     * @brief Retrieves the request payload.
     *
     * @return A reference to the vector of uint8_t containing the payload.
     */
    const std::vector<uint8_t>& getPayload() const;

    /**
     * @brief Sets the client ID for the request.
     *
     * @param clientId The unique client identifier (16 bytes).
     */
    void setClientId(const std::vector<uint8_t>& clientId);

    /**
     * @brief Sets the version number of the client protocol.
     *
     * @param version The version number as a uint8_t.
     */
    void setVersion(uint8_t version);

    /**
     * @brief Sets the request code.
     *
     * @param code The request code as a uint16_t.
     */
    void setCode(uint16_t code);

    /**
     * @brief Sets the payload size.
     *
     * @param payloadSize The size of the payload as a uint32_t.
     */
    void setPayloadSize(uint32_t payloadSize);

    /**
     * @brief Sets the payload content.
     *
     * @param payload A vector of uint8_t containing the new payload data.
     */
    void setPayload(const std::vector<uint8_t>& payload);

    /**
     * @brief Serializes the request into binary format for transmission.
     *
     * @return A vector of uint8_t representing the serialized request data.
     */
    std::vector<uint8_t> serialize() const;

private:
    std::vector<uint8_t> clientId; ///< 16-byte unique client identifier.
    uint8_t version;               ///< 1-byte protocol version.
    uint16_t code;                 ///< 2-byte request code.
    uint32_t payloadSize;          ///< 4-byte size of the payload.
    std::vector<uint8_t> payload;  ///< Variable-size request payload.
};

#endif // REQUEST_H
