#include "RegReconnect.h"
#include "ConnectionManager.h"

using namespace Constants;


// Constructor
RegReconnect::RegReconnect() {}

// Destructor
RegReconnect::~RegReconnect() {}

// Function to read IP, port, client name, and file path from transfer.info
bool RegReconnect::readFromTransfer(std::string& ip, std::string& port, std::string& clientName, std::string& filePath) {
	std::filesystem::path exePath = std::filesystem::current_path() / "transfer.info";

	std::ifstream transferFile(exePath.string());

	if (!transferFile.is_open()) {
		throw std::runtime_error("Error opening the transfer.info file!");
	}

	// Read the first line: IP:port
	std::string ipPort;

	std::getline(transferFile, ipPort);
	size_t find = ipPort.find(":");
	if (find == std::string::npos || ipPort.length() > MAX_IP_LENGTH + 1 + MAX_PORT_LENGTH) {
		throw std::runtime_error("Error: Invalid IP:port format or length exceeds limit. ipPort: " + ipPort);
	}
	ip = ipPort.substr(0, find);
	port = ipPort.substr(find + 1);
	std::cerr << "port " << port;
	// Read the second line: Client name
	std::getline(transferFile, clientName);
	if (clientName.length() > MAX_NAME_LENGTH) {
		clientName = clientName.substr(0, MAX_NAME_LENGTH - 1);
	}

	// Read the third line: File path
	std::getline(transferFile, filePath);
	if (filePath.length() > MAX_FILE_PATH_LENGTH) {
		throw std::runtime_error("Error: File path exceeds allowed length.");
	}

	transferFile.close();
	return true;
}


std::string RegReconnect::getEncryptedFileName(const std::string& fileName) {
	std::filesystem::path filePath(fileName);

	// Use ".enc" as the extension for encrypted files
	std::string encryptedFileName = filePath.stem().string() + ".enc";

	// Check if the length of encryptedFileName exceeds the limit for valid names
	if (encryptedFileName.size() > MAX_FILE_PATH_LENGTH - 1) {
		throw std::runtime_error("File name exceeds maximum allowed size.");
	}

	// Create a fixed size string
	std::string result(MAX_FILE_PATH_LENGTH, '\0'); // Prepares a string of size 255 filled with '\0'

	// Copy the content into the fixed size string
	std::memcpy(&result[0], encryptedFileName.data(), encryptedFileName.size());

	return result; // The last character will be '\0' due to resizing
}






std::vector<uint8_t> RegReconnect::createPayloadForRequest826(const std::string& name, const std::vector<uint8_t>& publicKey) {
	// Check if the public key size is exactly 160 bytes, throw an error if it's shorter
	if (publicKey.size() != 160) {
		throw std::invalid_argument("Public key must be exactly 160 bytes.");
	}

	// Total payload size: 255 bytes for the client name + 160 bytes for the public key
	std::vector<uint8_t> payload(MAX_CLIENT_NAME_LEN + PUBLIC_KEY_LEN, 0);

	// Determine the length of the client name (up to 254 bytes)
	size_t nameLength = std::min(name.size(), static_cast<size_t>(MAX_CLIENT_NAME_LEN - 1));

	// Copy the client name into the first 255 bytes, null-terminated
	std::copy(name.begin(), name.begin() + nameLength, payload.begin());
	payload[nameLength] = '\0';  // Null-terminate the name if it's shorter than 254 bytes

	// Copy the public key into the last 160 bytes
	std::copy(publicKey.begin(), publicKey.end(), payload.begin() + MAX_CLIENT_NAME_LEN);

	return payload;
}






std::vector<uint8_t> RegReconnect::buildPayload(
	uint32_t contentSize,
	uintmax_t origFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const std::string& fileName,
	const std::vector<uint8_t>& messageContent,
	const std::vector<uint8_t>& clientId)
{
	// Validate inputs
	if (fileName.size() > MAX_FILE_PATH_LENGTH) {
		throw std::runtime_error("Filename size " + std::to_string(fileName.size()) + " is too long. Maximum allowed length is 255 characters.");
	}
	if (messageContent.size() > CHUNKSIZE) {
		throw std::runtime_error("Message content is too large. Maximum allowed size is CHUNKSIZE bytes.");
	}
	if (contentSize > std::numeric_limits<uint32_t>::max()) {
		throw std::runtime_error("File size exceeds uint32_t limit!");
	}

	// Reserve space for the entire payload
	size_t totalSize = CONTENT_SIZE + 4 + 2 + 2 + MAX_FILE_PATH_LENGTH + messageContent.size();
	std::vector<uint8_t> payload(totalSize, 0); // Initialize with zeros

	// Add content size (4 bytes)
	std::memcpy(payload.data() + CONTENT_SIZE, &contentSize, sizeof(contentSize));

	// Add original file size (4 bytes)
	std::memcpy(payload.data(), &origFileSize, sizeof(origFileSize));

	// Add packet number (2 bytes)
	std::memcpy(payload.data() + 8, &packetNumber, sizeof(packetNumber));

	// Add total packets (2 bytes)
	std::memcpy(payload.data() + 10, &totalPackets, sizeof(totalPackets));

	// Add file name (255 bytes, zero-padded)
	std::memset(payload.data() + 12, 0, MAX_FILE_PATH_LENGTH); // Zero-fill for padding
	std::memcpy(payload.data() + 12, fileName.c_str(), std::min(fileName.size(), static_cast<size_t>(MAX_FILE_PATH_LENGTH - 1)));

	// Add message content (variable size)
	std::memcpy(payload.data() + 12 + MAX_FILE_PATH_LENGTH, messageContent.data(), messageContent.size());

	return payload;
}

// Function to split file into chunks and send them as payloads
void RegReconnect::sendEncryptedFileInChunks(
	uintmax_t origFileSize,
	const std::string& encryptedFileName,
	const std::string& fileName,
	const std::vector<uint8_t>& clientId,
	ConnectionManager& connection) {

	std::ifstream file(encryptedFileName, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << encryptedFileName << std::endl;
		return;
	}


	// Get the total file size
	file.seekg(0, std::ios::end);
	std::streampos encryptedfileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	if (encryptedfileSize > std::numeric_limits<uint32_t>::max()) {
		throw std::runtime_error("File size exceeds uint32_t limit!");
	}

	// Calculate total packets needed
	int totalPackets = static_cast<int>((static_cast<size_t>(encryptedfileSize) + CHUNKSIZE - 1) / CHUNKSIZE);
	int packetNumber = 0;

	std::vector<uint8_t> buffer(CHUNKSIZE);

	// Read the file in chunks and send each chunk
	while (file.read(reinterpret_cast<char*>(buffer.data()), CHUNKSIZE) || file.gcount() > 0) {
		packetNumber++;
		int bytesRead = file.gcount(); // Amount of data read in this chunk

		// Build the payload with the current chunk and metadata
		std::vector<uint8_t> sendFilePayload = buildPayload(
			encryptedfileSize,
			origFileSize,           // original file size
			packetNumber,           // current packet number
			totalPackets,           // total number of packets
			encryptedFileName,
			std::vector<uint8_t>(buffer.begin(), buffer.begin() + bytesRead),  // current file chunk (messageContent)
			clientId                // client ID
		);

		// Create a request to send the file data
		Request sendFileRequest(clientId, DEFAULT_VERSION, SEND_FILE_CODE, sendFilePayload);

		// Serialize the request and send it
		std::vector<uint8_t> serializedData = sendFileRequest.serialize();
		connection.sendData(serializedData);

		// Log progress
		std::cout << "Sent packet " << packetNumber << " of " << totalPackets << std::endl;
		std::cout << "Encrypted file size: " << encryptedfileSize << std::endl;
		std::cout << "Total packets: " << totalPackets << std::endl;
	}

	file.close();
}


bool RegReconnect::performRegistration(ConnectionManager& connection, RegReconnect& registration, std::string& ip, std::string& port, std::string& clientName, std::string& filePath) {
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

bool RegReconnect::sendRegisterRequest(ConnectionManager& connection, const std::string& clientName, std::vector<uint8_t>& bufferReceiveData, std::vector<uint8_t>& bufferUuid) {
	int attempts = 0;
	bool success = false;
	std::vector<uint8_t> serializedRequest;

	while (attempts < 3 && !success) {
		try {
			size_t usernameLength = std::min(clientName.size(), static_cast<size_t>(255));
			std::vector<uint8_t> clientNameBytes(clientName.begin(), clientName.end());

			clientNameBytes.assign(clientName.begin(), clientName.end());
			clientNameBytes.resize(MAX_NAME_LENGTH_PROTOCOL, '\0');
			std::cerr << "Client name: '" << clientName << "' (length: " << clientName.size() << ")" << std::endl;

			Request registerRequest(std::vector<uint8_t>(Constants::CLIENT_ID_SIZE, 0), DEFAULT_VERSION, REGISTER_REQUEST_CODE, clientNameBytes);
			serializedRequest = registerRequest.serialize();
			connection.sendData(serializedRequest);

			bufferReceiveData = connection.receiveData();
			success = Response::recvRegisterRequest(clientName, bufferReceiveData, bufferUuid);
			serializedRequest.clear();
		}
		catch (const std::exception& e) {
			std::cerr << "Server responded with an error: " << e.what() << std::endl;
		}
		attempts++;
	}
	return success;
}

std::vector<uint8_t> RegReconnect::readUuidFromFile() {
	const std::string filename = "me.info";
	std::ifstream mefile(filename);

	std::vector<uint8_t> bufferUuid(CLIENT_ID_SIZE, 0); // Initialize the buffer with zeros

	// Check if the file opened successfully
	if (!mefile.is_open()) {
		std::cerr << "Could not open file: " << filename << std::endl;
		return {}; // Return an empty vector on error
	}

	std::string line;

	// Skip the first line
	if (!std::getline(mefile, line)) {
		return {}; // Return an empty vector on read error
	}

	// Get the UUID
	if (std::getline(mefile, line)) {
		if (line.size() == CLIENT_ID_SIZE * 2) { // Check if the length is correct
			for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
				std::string byteString = line.substr(i * 2, 2);
				bufferUuid[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16)); // Convert from hex
			}
			std::cout << "UUID has been read into bufferUuid." << std::endl;
			return bufferUuid; // Return the populated vector
		}
		else {
			std::cerr << "UUID length is incorrect." << std::endl;
			return {}; // Return an empty vector on length error
		}
	}
	else {
		std::cerr << "Failed to read the second line." << std::endl;
		return {}; // Return an empty vector on read error
	}
}


