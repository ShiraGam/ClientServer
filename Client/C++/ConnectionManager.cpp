#include "ConnectionManager.h"
using namespace Constants;

// Constructor
ConnectionManager::ConnectionManager()
	: socket(io_context) {}

// Destructor
ConnectionManager::~ConnectionManager() {
	closeConnection();
}

// Connect to the server
void ConnectionManager::connectToServer(const std::string& ip, const std::string& port) {
	try {
		boost::asio::ip::tcp::resolver resolver(io_context);
		boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
		boost::asio::connect(socket, endpoints);
		std::cout << "Connected to server " << ip << " on port " << port << std::endl;
	}
	catch (std::exception& e) {
		std::cerr << "Error connecting to server: " << e.what() << std::endl;
	}
}

// Send data to server
void ConnectionManager::sendData(const std::vector<uint8_t>& data) {
	try {

		size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(data, data.size()));

	}
	catch (std::exception& e) {
		std::cerr << "Error sending binary data: " << e.what() << std::endl;
	}
}



// Receive data
std::vector<uint8_t>  ConnectionManager::receiveData() {
	try {
		std::vector<uint8_t> buffer(MAX_PAYLOAD_SIZE);
		// Create a deadline timer
		boost::asio::deadline_timer timer(io_context);
		timer.expires_from_now(boost::posix_time::seconds(TIMEOUT_SECONDS));

		// Start an async wait for the timer
		timer.async_wait([this](const boost::system::error_code& e) {
			if (!e) {
				// Timer expired
				socket.close();

			}
			});

		size_t reply_length = socket.read_some(boost::asio::buffer(buffer));

		if (reply_length == 0) {
			throw std::runtime_error("No data received from server.");
		}


		if (reply_length < HEADER_SIZE) {
			throw std::runtime_error("Incomplete response header.");
		}

		uint8_t version = Response::extractVersion(buffer);
		uint16_t code = Response::extractCode(buffer);
		uint32_t payload_size = Response::extractPayloadSize(buffer);

		if (version != DEFAULT_VERSION) {
			throw std::runtime_error("Invalid version received: " + std::to_string(static_cast<int>(version)));
		}

		std::cout << "Version: " << static_cast<int>(version) << std::endl;
		std::cout << "Code: " << code << std::endl;

		std::vector<uint8_t> payload = Response::extractPayload(buffer, reply_length, payload_size);

		if (payload.size() != payload_size) {
			throw std::runtime_error("Payload size mismatch: expected " + std::to_string(payload_size) + ", got " + std::to_string(payload.size()));
		}

		return buffer;
	}
	catch (const std::exception& e) {
		std::cerr << "Error receiving data: " << e.what() << std::endl;
		throw;
	}
}

// Close the connection
void ConnectionManager::closeConnection() {
	try {
		if (socket.is_open()) {
			socket.close();
			std::cout << "Connection closed." << std::endl;
		}
	}
	catch (std::exception& e) {
		std::cerr << "Error closing connection: " << e.what() << std::endl;
	}
}

