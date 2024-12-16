#ifndef RSA_KEY_H
#define RSA_KEY_H

#include <fstream>
#include <vector>
#include <string>
#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <rsa.h>
#include <string>
#include <osrng.h>     // For random number generator (AutoSeededRandomPool)
#include <hex.h>       // For Hex encoding 
#include <base64.h>    // For Base64 encoding 
#include "Constants.h"
#include <files.h>     // For saving/loading keys to/from files
#include "RegReconnect.h"

/**
 * @class RSAKey
 * @brief Handles RSA key generation, encryption, and file-related operations for managing RSA keys.
 */
class RSAKey {
public:
    /**
     * @brief Generates an RSA key pair with a specified bit length.
     *
     * @param publicKey Reference to store the generated RSA public key.
     * @param privateKey Reference to store the generated RSA private key.
     */
    void GenerateRSAKeyPair(CryptoPP::RSA::PublicKey& publicKey, CryptoPP::RSA::PrivateKey& privateKey);

    /**
     * @brief Converts a public RSA key to DER format.
     *
     * @param publicKey The RSA public key to convert.
     * @return A vector of uint8_t containing the public key in DER format.
     */
    static std::vector<uint8_t> publicKeyToDER(const CryptoPP::RSA::PublicKey& publicKey);

    /**
     * @brief Decrypts an encrypted key using an RSA private key.
     *
     * @param encryptedKey A vector of uint8_t containing the encrypted AES key.
     * @param privateKey The RSA private key used for decryption.
     * @return A vector of uint8_t representing the decrypted AES key.
     */
    static std::vector<uint8_t> decryptKey(const std::vector<uint8_t>& encryptedKey, const CryptoPP::RSA::PrivateKey& privateKey);

    /**
     * @brief Encrypts a file using an AES key.
     *
     * @param decryptedAESKey The AES key used for encryption, in a decrypted format.
     * @param fileName The name of the file to be encrypted.
     */
    static void encryptFile(const std::vector<uint8_t>& decryptedAESKey, const std::string& fileName);

    /**
     * @brief Loads an RSA private key from a file.
     *
     * @param privateKey Reference to store the loaded private key.
     * @throws std::runtime_error if the file cannot be loaded.
     */
    static void LoadPrivateKeyFromFile(CryptoPP::RSA::PrivateKey& privateKey);

    /**
     * @brief Appends an RSA private key to a file.
     *
     * @param privateKey The RSA private key to be saved.
     */
    static void appendPrivateKeyToFile(const CryptoPP::RSA::PrivateKey& privateKey);

private:
    /**
     * @brief Saves an RSA private key to a specified file.
     *
     * @param privateKey The RSA private key to be saved.
     * @param filename The name of the file where the private key will be saved.
     */
    void SavePrivateKeyToFile(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& filename);
};

#endif // RSA_KEY_H
