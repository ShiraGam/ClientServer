#include"Response.h"

using namespace Constants;
// Extract version
uint8_t Response::extractVersion(const std::vector<uint8_t>& buffer) {
	return buffer[0];
}

// Extract code
uint16_t Response::extractCode(const std::vector<uint8_t>& buffer) {
	return boost::endian::little_to_native<uint16_t>(*reinterpret_cast<const uint16_t*>(&buffer[1]));
}

// Extract payload size
uint32_t Response::extractPayloadSize(const std::vector<uint8_t>& buffer) {
	uint32_t payload_size = boost::endian::little_to_native(*reinterpret_cast<const uint32_t*>(&buffer[3]));
	if (payload_size > MAX_PAYLOAD_SIZE) {
		throw std::runtime_error("Payload size exceeds maximum allowed limit (1024 bytes).");
	}
	return payload_size;
}

// Extract payload
std::vector<uint8_t> Response::extractPayload(const std::vector<uint8_t>& buffer, size_t reply_length, uint32_t payload_size) {
	if (reply_length - HEADER_SIZE < payload_size) {
		throw std::runtime_error("Incomplete payload received.");
	}
	return std::vector<uint8_t>(buffer.begin() + HEADER_SIZE, buffer.begin() + HEADER_SIZE + payload_size);
}

bool Response::recvRegisterRequest(const std::string& clientName, const std::vector<uint8_t>& buffer, std::vector<uint8_t>& bufferUuid) {

	// Check if the response code is 1600 (success)
	std::cerr << "Receive notification of registration " << Response::extractCode(buffer) << std::endl;
	if (Response::extractCode(buffer) == RESPONSE_SUCCESS ||
		Response::extractCode(buffer) == RESPONSE_RECONNECT_FAILED) {
		try {
			// Extract the payload (ID) from the response
			bufferUuid = Response::extractPayload(buffer, buffer.size(), Response::extractPayloadSize(buffer));

			// Ensure the payload (ID) has the expected size(A check has already been made that the PayloadSize corresponds to the real size)
			if (Response::extractPayloadSize(buffer) != CLIENT_ID_SIZE) {
				throw std::runtime_error("Invalid payload size received.");
			}

			// Convert the ID to ASCII (Hex)
			std::stringstream idStream;
			for (const auto& byte : bufferUuid) {
				idStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			std::string clientId = idStream.str();

			// Write the client name and ID to the me.info file
			std::ofstream outfile("me.info");
			if (!outfile.is_open()) {
				throw std::runtime_error("Failed to open me.info for writing.");
				return false;
			}

			outfile << clientName << std::endl;  // Write the client name
			outfile << clientId << std::endl;    // Write the unique ID in Hex format
			outfile.close();

			std::cout << "Client name and ID written to me.info " << std::endl;
			return true;
		}
		catch (const std::exception& e) {
			std::cerr << "Error processing server response: " << e.what() << std::endl;
			throw;
		}

	}
	else {
		std::cerr << "Registration failed: invalid response code. " << std::endl;
	}

	// If the response code is not 1600, the registration failed
	std::cerr << "Registration failed: invalid response code." << std::endl;
	return false;
}
