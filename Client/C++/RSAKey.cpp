#include "RSAKey.h"

using namespace CryptoPP;
using namespace Constants;

void RSAKey::GenerateRSAKeyPair(RSA::PublicKey& publicKey, CryptoPP::RSA::PrivateKey& privateKey) {
	try {
		AutoSeededRandomPool rng;

		// Generate RSA keys
		privateKey.GenerateRandomWithKeySize(rng, KEY_LENGTH);  // Generate key of specified length
		publicKey.AssignFrom(privateKey);                        // Assign public key from private key

		// Save the private key to a file
		SavePrivateKeyToFile(privateKey, "priv.key");

	}
	catch (const Exception& ex) {
		std::cerr << "Error generating RSA keys: " << ex.what() << std::endl;
		throw;
	}
}

void RSAKey::SavePrivateKeyToFile(const RSA::PrivateKey& privateKey, const std::string& filename) {
	try {
		// Create a file stream to save the Base64-encoded private key
		std::ofstream privateKeyFile(filename, std::ios::binary);
		if (!privateKeyFile.is_open()) {
			throw std::runtime_error("Unable to open file for writing private key.");
		}

		// Create a Base64Encoder to encode the key to Base64 format
		Base64Encoder encoder(new FileSink(privateKeyFile));  // Encode directly into the file

		// Encode the private key in DER format
		privateKey.DEREncode(encoder);  // Encode the private key in DER format
		encoder.MessageEnd();           // Finalize the encoding

		privateKeyFile.close();         // Close the file after writing
		std::cout << "Private key saved to " << filename << " in Base64 format." << std::endl;
	}
	catch (const std::exception& ex) {
		std::cerr << "Error saving private key: " << ex.what() << std::endl;
		throw;
	}
}

std::vector<uint8_t> RSAKey::publicKeyToDER(const CryptoPP::RSA::PublicKey& publicKey) {
	CryptoPP::ByteQueue queue;
	publicKey.Save(queue);  // Save the public key in DER format to the queue

	size_t keySize = queue.MaxRetrievable();
	std::vector<uint8_t> derKey(keySize);
	queue.Get(derKey.data(), keySize);  // Copy the data into the vector

	return derKey;
}

std::vector<uint8_t> RSAKey::decryptKey(const std::vector<uint8_t>& encryptedKey, const RSA::PrivateKey& privateKey) {
	try {
		// Use secure RNG
		AutoSeededRandomPool rng;

		// Setup RSA decryption with OAEP + SHA
		RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

		// Print the received encrypted AES key on the client side
		std::stringstream encryptedStream;
		for (const auto& byte : encryptedKey) {
			encryptedStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}

		// Allocate space for the decrypted AES key
		size_t maxSize = decryptor.FixedMaxPlaintextLength(/*encryptedKey.size()*/);
		if (maxSize == 0) {
			throw std::runtime_error("Invalid encrypted key size.");
		}

		std::vector<uint8_t> decryptedKey(maxSize);

		// Decrypt the AES key using RSA private key
		CryptoPP::DecodingResult result = decryptor.Decrypt(rng, encryptedKey.data(), encryptedKey.size(), decryptedKey.data());

		// Resize the vector to the actual size of the decrypted key (using messageLength)
		decryptedKey.resize(result.messageLength);

		// Print the decrypted AES key
		std::stringstream decryptedStream;
		for (const auto& byte : decryptedKey) {
			decryptedStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}
		std::string decryptedKeyHex = decryptedStream.str();
		std::cout << "Decrypted AES Key (Client): " << decryptedKeyHex << std::endl;

		// Print the decrypted key size
		std::cout << "Decrypted AES Key Size (Client): " << decryptedKey.size() << " bytes" << std::endl;

		// Securely return the decrypted AES key
		return decryptedKey;
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Decryption error: " << e.what() << std::endl;
		throw;
	}
	catch (const std::exception& e) {
		std::cerr << "General error: " << e.what() << std::endl;
		throw;
	}
}



void RSAKey::encryptFile(const std::vector<uint8_t>& decryptedAESKey, const std::string& fileName) {
	// The key size should be 32 bytes (for AES-256)
	if (decryptedAESKey.size() != AES_KEY_LENGTH) {
		throw std::runtime_error("Invalid AES key length. Expected 256-bit key. AES length is ");
	}



	// Read the content of the file
	std::ifstream file(fileName, std::ios::binary);
	std::cout << "Opening file: " << fileName << std::endl;
	if (!file.is_open()) {
		throw std::runtime_error("Unable to open file.");
	}
	std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();

	// Create an IV filled with zeros (16 bytes for AES)
	std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE, 0);

	// Create CBC mode AES
	std::string cipherText;
	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		encryptor.SetKeyWithIV(decryptedAESKey.data(), decryptedAESKey.size(), iv.data());

		// Encrypt the data
		CryptoPP::StringSource ss(fileData.data(), fileData.size(), true,
			new CryptoPP::StreamTransformationFilter(encryptor,
				new CryptoPP::StringSink(cipherText)
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		throw std::runtime_error("Encryption error: " + std::string(e.what()));
	}

	// Create a new file and write the encrypted data
	std::ofstream outFile(RegReconnect::getEncryptedFileName(fileName), std::ios::binary);  // Create a new file for encrypted data
	std::cout << "Writing to encrypted file: " << RegReconnect::getEncryptedFileName(fileName) << std::endl;
	if (!outFile.is_open()) {
		throw std::runtime_error("Unable to open output file.");
	}

	// Write only the encrypted content
	outFile.write(cipherText.data(), cipherText.size());
	outFile.close();
}

void RSAKey::appendPrivateKeyToFile(const CryptoPP::RSA::PrivateKey& privateKey) {
	// Open the file in append mode to preserve existing lines
	std::ofstream meFile("me.info", std::ios::app);
	if (!meFile.is_open()) {
		throw std::runtime_error("Unable to open me.info for appending private key.");
	}

	// Prepare a Base64 encoder
	std::string encodedKey;
	CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encodedKey));
	privateKey.DEREncode(encoder); // Encode the private key in DER format
	encoder.MessageEnd(); // Finalize encoding

	// Write a newline, then the private key on the third line
	meFile << "\n" << encodedKey;
	meFile.close();

	std::cout << "Private key appended to me.info in Base64 format on the third line." << std::endl;
}

void RSAKey::LoadPrivateKeyFromFile(CryptoPP::RSA::PrivateKey& privateKey)
{
	try {
		// Open the private key file
		std::ifstream privateKeyFile("priv.key", std::ios::binary);
		if (!privateKeyFile.is_open()) {
			throw std::runtime_error("Unable to open private key file.");
		}

		// Create a Base64Decoder to decode the key from Base64 format
		Base64Decoder decoder;
		FileSource file(privateKeyFile, true, new Redirector(decoder));

		// Decode and load the private key in DER format
		privateKey.BERDecode(decoder);

		std::cout << "Private key loaded from successfully." << std::endl;

		privateKeyFile.close();
	}
	catch (const std::exception& ex) {
		std::cerr << "Error loading private key: " << ex.what() << std::endl;
		throw;
	}
}



