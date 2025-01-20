#include "CryptoConnectionHandler.h"

using namespace Constants;
using namespace CryptoPP;

// Continue implementing other methods as defined in the header
size_t CryptoConnectionHandler::GetPublicKeySize(const RSA::PublicKey& publicKey) {
	ByteQueue queue;
	publicKey.Save(queue); // Save the key to a ByteQueue
	return queue.CurrentSize(); // Return the size of the key in bytes
}

std::vector<uint8_t> CryptoConnectionHandler::decryptAESKeyFromPayload(const std::vector<uint8_t>& bufferReceiveData, const std::vector<uint8_t>& bufferUuid,
	CryptoPP::RSA::PrivateKey& privateKey) {
	auto payloadSize = Response::extractPayloadSize(bufferReceiveData);
	auto payload = Response::extractPayload(bufferReceiveData, bufferReceiveData.size(), payloadSize);

	if (payload.size() > CLIENT_ID_SIZE && std::equal(payload.begin(), payload.begin() + CLIENT_ID_SIZE, bufferUuid.begin())) {
		std::vector<uint8_t> encryptedAESKey(payload.begin() + CLIENT_ID_SIZE, payload.end());
		return RSAKey::decryptKey(encryptedAESKey, privateKey); // Return the decrypted AES key
	}
	else {
		throw std::runtime_error("Invalid payload or client ID mismatch.");
	}
}

int CryptoConnectionHandler::extractCrcServer(const std::vector<uint8_t>& bufferReceiveData) {

	auto payloadSize = Response::extractPayloadSize(bufferReceiveData);
	auto payload = Response::extractPayload(bufferReceiveData, bufferReceiveData.size(), payloadSize);

	if (payload.size() == CLIENT_ID_SIZE + CONTENT_SIZE + MAX_FILE_PATH_LENGTH + CKSUM) {
		std::vector<uint8_t> server_crc(payload.end() - CKSUM, payload.end());

		if (server_crc.size() >= sizeof(int)) {
			int crcValue;
			std::copy(server_crc.begin(), server_crc.begin() + sizeof(int), reinterpret_cast<uint8_t*>(&crcValue));
			return crcValue;
		}
		else {
			throw std::runtime_error("Invalid CRC size.");
		}
	}
	else {
		throw std::runtime_error("Invalid payload or client ID mismatch.");
		return -1;
	}
}

void CryptoConnectionHandler::sendCRCValidationRequest(ConnectionManager& connection, const std::vector<uint8_t>& bufferUuid, int code, const std::vector<uint8_t>& encryptedFileNameBytes) {
	Request crcValidationRequest(bufferUuid, DEFAULT_VERSION, code, encryptedFileNameBytes);
	std::vector<uint8_t> serializedRequest = crcValidationRequest.serialize();
	connection.sendData(serializedRequest);
}

bool CryptoConnectionHandler::handleServerResponse(ConnectionManager& connection, const std::vector<uint8_t>& bufferUuid, const std::vector<uint8_t>& encryptedFileNameBytes,
	int crcClient, uintmax_t filesize, std::string filePath) {

	for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
		std::vector<uint8_t> bufferReceiveData = connection.receiveData();
		int serverCode = Response::extractCode(bufferReceiveData);

		// If code is not 1603, send request with code 900 and retry
		if (serverCode != RESPONSE_CRC_VERIFIED) {
			sendCRCValidationRequest(connection, bufferUuid, CRC_VALIDATION_CODE, encryptedFileNameBytes);
			std::cerr << "Attempt " << attempt << ": Sent code 900, server response not 1603.\n";
		}
		// If server code is 1603, check CRC match
		else {
			int crcServer = extractCrcServer(bufferReceiveData);
			if (crcClient != crcServer) {
				sendCRCValidationRequest(connection, bufferUuid, CRC_ERROR_CODE, encryptedFileNameBytes);
				RegReconnect::sendEncryptedFileInChunks(filesize, RegReconnect::getEncryptedFileName(filePath), filePath, bufferUuid, connection);
				std::cerr << "Attempt " << attempt << ": Sent code 901, CRC mismatch.\n";
			}
			else {
				// CRC is valid
				std::cout << "CRC validated and code 1603 acknowledged.\n";
				return true; // Successful validation
			}
		}
	}
	// Final attempt with code 902 if all retries failed
	sendCRCValidationRequest(connection, bufferUuid, FINAL_CRC_ERROR_CODE, encryptedFileNameBytes);
	std::cerr << "Final attempt failed. Sent code 902.\n";
	return false; // Validation failed after retries
}



void CryptoConnectionHandler::crcCheck(ConnectionManager& connection, const std::string& filePath, const std::vector<uint8_t>& bufferUuid,
	uintmax_t filesize) {
	std::string encryptedFileName = RegReconnect::getEncryptedFileName(filePath);
	std::vector<uint8_t> encryptedFileNameBytes(encryptedFileName.begin(), encryptedFileName.end());

	try {
		int crcClient = static_cast<int>(readfile(filePath));
		std::cout << "Starting CRC checking...\n";
		if (!handleServerResponse(connection, bufferUuid, encryptedFileNameBytes, crcClient, filesize, filePath)) {
			std::cerr << "CRC validation failed after all attempts.\n";
		}
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Crypto++ error: " << e.what() << '\n';
	}
	catch (const std::exception& e) {
		std::cerr << "Standard exception: " << e.what() << '\n';
	}
}

bool performRegistration(ConnectionManager& connection, RegReconnect& registration, std::string& ip, std::string& port, std::string& clientName, std::string& filePath) {
	try {
		std::cout << "Starting registration." << std::endl;
		registration.readFromTransfer(ip, port, clientName, filePath);
		connection.connectToServer(ip, port);
		return true;
	}
	catch (const std::exception& e) {
		std::cerr << "Error in registration: " << e.what() << std::endl;
		return false;
	}
}

bool sendRegisterRequest(ConnectionManager& connection, const std::string& clientName, std::vector<uint8_t>& bufferReceiveData, std::vector<uint8_t>& bufferUuid) {
	int attempts = 0;
	bool success = false;

	while (attempts < MAX_ATTEMPTS && !success) {
		try {
			std::vector<uint8_t> clientNameBytes(clientName.begin(), clientName.end());
			clientNameBytes.assign(clientName.begin(), clientName.end());
			clientNameBytes.resize(MAX_NAME_LENGTH_PROTOCOL, '\0');

			Request registerRequest(std::vector<uint8_t>(Constants::CLIENT_ID_SIZE, 0), DEFAULT_VERSION, REGISTER_REQUEST_CODE, clientNameBytes);
			std::vector<uint8_t> serializedRequest = registerRequest.serialize();
			std::cout << "Sending request with payload: ";
			for (const auto& byte : serializedRequest) {
				printf("%02X ", byte);
			}
			std::cout << std::endl;
			connection.sendData(serializedRequest);
			bufferReceiveData = connection.receiveData();
			success = Response::recvRegisterRequest(clientName, bufferReceiveData, bufferUuid);
		}
		catch (const std::exception& e) {
			std::cerr << "Server responded with an error: " << e.what() << std::endl;
			attempts++;
		}
	}
	return success;
}

std::vector<uint8_t> CryptoConnectionHandler::receiveAESKeyWithRetries(ConnectionManager& connection,
	const std::vector<uint8_t>& bufferUuid,
	CryptoPP::RSA::PrivateKey& privateKey,
	const std::string& clientName,
	std::vector<uint8_t> publicKeyDER
) {
	std::vector<uint8_t> decryptedAESKey;
	int attempts = 0;

	while (attempts < MAX_ATTEMPTS) {
		std::vector<uint8_t> bufferReceiveData(MAX_PAYLOAD_SIZE, 0);
		bufferReceiveData = connection.receiveData();

		int responseCode = Response::extractCode(bufferReceiveData);
		std::cerr << "Attempt " << (attempts + 1) << ": Received response code: " << responseCode << std::endl;

		if (responseCode == RESPONSE_AES_KEY_RECEIVED) {
			decryptedAESKey = decryptAESKeyFromPayload(bufferReceiveData, bufferUuid, privateKey);
			return decryptedAESKey;
		}
		else {
			std::cerr << "Attempt " << (attempts + 1) << ": Failed to receive expected AES key. Response code: "
				<< responseCode << std::endl;
			Request publicKeyReq(bufferUuid, DEFAULT_VERSION, PUBLIC_KEY_REQUEST_CODE, RegReconnect::createPayloadForRequest826(clientName, publicKeyDER));

			// Serialize the request to send it over the network
			std::vector<uint8_t> serializedRequest = publicKeyReq.serialize();
			connection.sendData(serializedRequest);

			attempts++;
		}
	}

	throw std::runtime_error("Failed to receive AES key after " + std::to_string(MAX_ATTEMPTS) + " attempts.");
}

std::vector<uint8_t> CryptoConnectionHandler::reconnectAndReceiveAESKey(ConnectionManager& connection,
	std::vector<uint8_t>& bufferUuid,
	CryptoPP::RSA::PrivateKey& privateKey,
	std::string clientName,
	CryptoPP::RSA::PublicKey& publicKey) {
	std::vector<uint8_t> decryptedAESKey;
	int attempts = 0;
	bool success = false;
	while (attempts <= MAX_ATTEMPTS && !success) {
		// Send reconnect request and receive data
		try {
			std::vector<uint8_t> bufferReceiveData = connection.receiveData();

			// Check the response code
			if (Response::extractCode(bufferReceiveData) == RESPONSE_RECONNECT_SUCCESS) {
				// Try to decrypt the AES key from the payload
				decryptedAESKey = decryptAESKeyFromPayload(bufferReceiveData, bufferUuid, privateKey);
				return decryptedAESKey; // Return the successfully decrypted AES key
			}
			else if (Response::extractCode(bufferReceiveData) == RESPONSE_RECONNECT_FAILED) {
				bufferUuid = Response::extractPayload(bufferReceiveData, bufferReceiveData.size(), Response::extractPayloadSize(bufferReceiveData));
				success = Response::recvRegisterRequest(clientName, bufferReceiveData, bufferUuid);
				generateAndSendPublicKey(clientName, connection, bufferReceiveData, publicKey, privateKey, decryptedAESKey);

			}
			else {
				std::cerr << "Attempt " << (attempts + 1) << ": Reconnecting to the server failed. Response code: "
					<< Response::extractCode(bufferReceiveData) << std::endl;
			}
		}
		catch (const std::exception& e) {
			std::cerr << "Attempt " << (attempts + 1) << ": Decrypting AES key failed: " << e.what() << std::endl;
		}


		attempts++;
	}
	throw std::runtime_error("Failed to reconnect and receive AES key.");
}

void CryptoConnectionHandler::generateAndSendPublicKey(const std::string& clientName,
	ConnectionManager& connection,
	const std::vector<uint8_t>& bufferReceiveData,
	CryptoPP::RSA::PublicKey& publicKey,
	CryptoPP::RSA::PrivateKey& privateKey,
	std::vector<uint8_t>& decryptedAESKey) {
	try {
		// Generate the RSA key pair
		RSAKey rsaKey; // Assuming RSAKey is already defined somewhere
		rsaKey.GenerateRSAKeyPair(publicKey, privateKey);
		std::cout << "RSA key pair generation successful!" << std::endl;

		// Copy the username into the first 255 bytes
		std::vector<uint8_t> payload(MAX_CLIENT_NAME_LEN, 0);
		size_t usernameLength = std::min(clientName.size(), (size_t)MAX_CLIENT_NAME_LEN);
		std::copy(clientName.begin(), clientName.begin() + usernameLength, payload.begin());



		// Convert the public key to DER format
		std::vector<uint8_t> publicKeyDER = RSAKey::publicKeyToDER(publicKey);

		// Save private key to file
		RSAKey::appendPrivateKeyToFile(privateKey);

		// Create the Request object for code 826
		std::vector<uint8_t> binaryUuid = RegReconnect::readUuidFromFile();

		Request publicKeyReq(binaryUuid, DEFAULT_VERSION, PUBLIC_KEY_REQUEST_CODE, RegReconnect::createPayloadForRequest826(clientName, publicKeyDER));

		// Serialize the request to send it over the network
		std::vector<uint8_t> serializedRequest = publicKeyReq.serialize();

		connection.sendData(serializedRequest);

		// Attempt to receive the AES key
		decryptedAESKey = receiveAESKeyWithRetries(connection, binaryUuid, privateKey, clientName, publicKeyDER);
	}
	catch (const std::exception& e) {
		std::cerr << "Error during public key generation and sending: " << e.what() << std::endl;
		throw;
	}
}

