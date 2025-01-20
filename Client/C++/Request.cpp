#include "Request.h"
#include "Constants.h"
#include <iostream>


// Initialize version to the default version
Request::Request()
	: version(Constants::DEFAULT_VERSION), code(0), payloadSize(0) {
	clientId.resize(Constants::CLIENT_ID_SIZE, 0); // Initialize Client ID with 16 bytes
}

Request::Request(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload)
	: clientId(clientId), version(version), code(code), payload(payload) {

	payloadSize = static_cast<uint32_t>(payload.size());
}


// Getter implementations
const std::vector<uint8_t>& Request::getClientId() const {
	return clientId;
}

uint8_t Request::getVersion() const {
	return version;
}

uint16_t Request::getCode() const {
	return code;
}

uint32_t Request::getPayloadSize() const {
	return payloadSize;
}

const std::vector<uint8_t>& Request::getPayload() const {
	return payload;
}

// Setter 
void Request::setClientId(const std::vector<uint8_t>& clientId) {
	if (clientId.size() != Constants::CLIENT_ID_SIZE) {
		throw std::invalid_argument("Client ID must be exactly 16 bytes.");
	}
	this->clientId = clientId;
}

void Request::setVersion(uint8_t version) {
	this->version = version;
}

void Request::setCode(uint16_t code) {
	this->code = code;
}

void Request::setPayloadSize(uint32_t payloadSize) {
	this->payloadSize = payloadSize;
}

void Request::setPayload(const std::vector<uint8_t>& payload) {
	this->payload = payload;
}

// Helper function to convert 16-bit values to little-endian format
std::vector<uint8_t> toLittleEndian(uint16_t value) {
	return {
		static_cast<uint8_t>(value & 0xFF),        // Least significant byte
		static_cast<uint8_t>((value >> 8) & 0xFF)  // Most significant byte
	};
}

// Helper function to convert 32-bit values to little-endian format
std::vector<uint8_t> toLittleEndian(uint32_t value) {
	return {
		static_cast<uint8_t>(value & 0xFF),        // Least significant byte
		static_cast<uint8_t>((value >> 8) & 0xFF),
		static_cast<uint8_t>((value >> 16) & 0xFF),
		static_cast<uint8_t>((value >> 24) & 0xFF) // Most significant byte
	};
}

// Function to serialize the request into binary format for sending over the network
std::vector<uint8_t> Request::serialize() const {
	std::vector<uint8_t> data;

	// Add Client ID (16 bytes)
	data.insert(data.end(), clientId.begin(), clientId.end());

	// Add Version (1 byte)
	data.push_back(version);

	// Add Code (2 bytes) in little-endian
	std::vector<uint8_t> codeLE = toLittleEndian(code);
	data.insert(data.end(), codeLE.begin(), codeLE.end());

	// Add Payload Size (4 bytes) in little-endian
	std::vector<uint8_t> payloadSizeLE = toLittleEndian(payloadSize);
	data.insert(data.end(), payloadSizeLE.begin(), payloadSizeLE.end());

	// Add Payload (variable size)
	data.insert(data.end(), payload.begin(), payload.end());

	return data;
}



