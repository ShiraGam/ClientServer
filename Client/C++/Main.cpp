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
#include "CryptoConnectionHandler.h"

using namespace CryptoPP;
using namespace Constants;

int main() {
	// Create an instance of ConnectionMnager.
	ConnectionManager connection;
	RegReconnect registration;
	std::string ip, port, clientName, filePath;
	std::vector<uint8_t> bufferReceiveData(MAX_PAYLOAD_SIZE);
	std::vector<uint8_t> bufferUuid(CLIENT_ID_SIZE);
	std::vector<uint8_t> payload(MAX_PAYLOAD_SIZE - HEADER_LENGTH, 0);//payloade
	std::vector<uint8_t> serializedRequest;
	std::vector<uint8_t> clientNameBytes(MAX_NAME_LENGTH_PROTOCOL);
	std::vector<uint8_t> decryptedAESKey;
	std::vector<uint8_t>  encryptedFileNameBytes;
	int attempts = 0; // Initialize attempts counter
	bool success = false; // Flag to indicate success
	// Declare RSA key pair
	CryptoPP::RSA::PublicKey publicKey;
	CryptoPP::RSA::PrivateKey privateKey;
	uint32_t filesize = 0;


	// Open the "me.info" file.
	std::ifstream mefile("me.info");


	if (!mefile.is_open()) {


		// Registration process
		if (!registration.performRegistration(connection, registration, ip, port, clientName, filePath)) {
			std::cerr << "Registration failed." << std::endl;
			return -1;
		}

		if (!registration.sendRegisterRequest(connection, clientName, bufferReceiveData, bufferUuid)) {
			std::cerr << "Failed to send registration request." << std::endl;
			return -1;
		}

		try {
			CryptoConnectionHandler::generateAndSendPublicKey(clientName, connection, bufferReceiveData, publicKey, privateKey, decryptedAESKey);
		}
		catch (const CryptoPP::Exception& e) {
			std::cerr << "Crypto++ error: " << e.what() << std::endl;
			connection.closeConnection();
			return -1;
		}
		catch (const std::exception& e) {
			std::cerr << "Standard exception: " << e.what() << std::endl;
			connection.closeConnection();
			return -1;
		}

	}
	//reconnection
	else {
		try {
			std::cout << "Reconnecting to the server." << std::endl;

			registration.readFromTransfer(ip, port, clientName, filePath);
			connection.connectToServer(ip, port);

			serializedRequest.clear();
			bufferReceiveData.clear();
			//read uuid from me.info
			bufferUuid = RegReconnect::readUuidFromFile();
			// get private key
			RSAKey::LoadPrivateKeyFromFile(privateKey);

			std::vector<uint8_t> clientNameBinary(clientName.begin(), clientName.end());

			clientNameBytes.assign(clientName.begin(), clientName.end());
			clientNameBytes.resize(MAX_NAME_LENGTH_PROTOCOL, '\0');

			Request reconnectReqest(bufferUuid, DEFAULT_VERSION, RECONNECT_REQUEST_CODE, clientNameBinary);
			serializedRequest = reconnectReqest.serialize();
			connection.sendData(serializedRequest);

			decryptedAESKey = CryptoConnectionHandler::reconnectAndReceiveAESKey(connection, bufferUuid, privateKey, clientName, publicKey);

		}
		catch (const CryptoPP::Exception& e) {
			std::cerr << "Crypto++ error: " << e.what() << std::endl;
			connection.closeConnection();
			return -1;
		}
		catch (const std::exception& e) {
			std::cerr << "Standard exception: " << e.what() << std::endl;
			connection.closeConnection();
			return -1;
		}
	}


	//get the size of original file
	try {
		std::filesystem::path path(filePath);

		if (std::filesystem::exists(path) && std::filesystem::is_regular_file(path)) {
			uintmax_t filesize = std::filesystem::file_size(path);
			std::cout << "The size of the file is: " << filesize << " bytes." << std::endl;
		}
		else {
			std::cerr << "The file does not exist or is not a regular file." << std::endl;
		}
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		connection.closeConnection();
		return -1;
	}
	try {
		bufferUuid.clear();
		bufferUuid = RegReconnect::readUuidFromFile();
	}
	catch (const std::exception& e) {
		connection.closeConnection();
		std::cerr << "Error: " << e.what() << std::endl;
		return -1;
	}
	//encypte the file and send it to the servser
	try {
		RSAKey::encryptFile(decryptedAESKey, filePath);
		std::cout << "File encrypted successfully!" << std::endl;
		RegReconnect::sendEncryptedFileInChunks(filesize, RegReconnect::getEncryptedFileName(filePath), filePath, bufferUuid, connection);

	}
	catch (const std::exception& e) {
		connection.closeConnection();
		std::cerr << "Error: " << e.what() << std::endl;
		return -1;
	}
	try {
		CryptoConnectionHandler::crcCheck(connection, filePath, bufferUuid, filesize);
	}
	catch (const std::exception& e) { std::cerr << "Error: " << e.what() << std::endl; connection.closeConnection(); return -1; }

	// Close the connection.
	connection.closeConnection();
	return 0;
}


