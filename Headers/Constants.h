#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>
#include <cstddef>

namespace Constants {
	// Constants for protocol sizes
	static const size_t CLIENT_ID_SIZE = 16;
	static const size_t VERSION_SIZE = 1;
	static const size_t CODE_SIZE = 2;
	static const size_t PAYLOAD_SIZE_FIELD = 4;
	const uint8_t DEFAULT_VERSION = 3;
	const int KEY_LENGTH = 1024;
	const uint32_t MAX_PAYLOAD_SIZE = 1024;
	const size_t HEADER_SIZE = 7;  // 1 byte version + 2 bytes code + 4 bytes payload size
	const int MAX_ATTEMPTS = 3;
	const int MAX_IP_LENGTH = 15;
	const int MAX_PORT_LENGTH = 5;
	const int MAX_NAME_LENGTH = 100;
	const int MAX_FILE_PATH_LENGTH = 255;
	const int MAX_NAME_LENGTH_PROTOCOL = 255;
	const int MAX_CLIENT_NAME_LEN = 255;
	const int AES_KEY_LENGTH = 32;
	const int CHUNKSIZE = 1024 * 1024;
	const int CONTENT_SIZE = 4;
	const int CKSUM = 4;
	const int HEADER_LENGTH = 23;
	const int PUBLIC_KEY_LEN = 160;
	const int TIMEOUT_SECONDS = 5;



	// Request Codes
	const uint16_t REGISTER_REQUEST_CODE = 825;
	const uint16_t PUBLIC_KEY_REQUEST_CODE = 826;
	const uint16_t RECONNECT_REQUEST_CODE = 827;
	const uint16_t SEND_FILE_CODE = 828;
	const uint16_t CRC_VALIDATION_CODE = 900;
	const uint16_t CRC_ERROR_CODE = 901;
	const uint16_t FINAL_CRC_ERROR_CODE = 902;

	// Response Codes
	const int  RESPONSE_SUCCESS = 1600;
	const int RESPONSE_REGISTRATION_FAILED = 1601;
	const int  RESPONSE_AES_KEY_RECEIVED = 1602;
	const int  RESPONSE_CRC_VERIFIED = 1603;
	const int RESPONSE_FILE_TOO_LARGE = 1604;
	const int RESPONSE_RECONNECT_SUCCESS = 1605;
	const int RESPONSE_RECONNECT_FAILED = 1606;
	const int RESPONSE_UNKNOWN_ERROR = 1607;



}

#endif // CONSTANTS_H

