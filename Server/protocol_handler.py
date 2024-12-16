import binascii
import struct
import traceback
import uuid
from Crypto.Random import get_random_bytes
import logging

from config.constants import HEADER_SIZE, UUID_SIZE, AES_KEY_256, MAX_FILE_SIZE
from protocol_handler_helpers import ProtocolHandlerHelpers
from config import constants
import encryption_utils
from response import Response
from client_data import get_client, add_client, print_all_clients, clients_data, client_name_exists


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class ProtocolHandler:
    """Handles protocol messages and routes them to the appropriate handler."""

    def __init__(self):
        self.helpers = ProtocolHandlerHelpers()

    def handle_message(self, client_socket, message: bytes):
        """Dispatch the message to the appropriate handler based on the message code."""
        try:
            if not isinstance(message, bytes):
                raise ValueError("Invalid message format. Expected bytes.")

            client_id, version, code, payload_size = ProtocolHandlerHelpers.parse_header(message)

            client = get_client(client_id)

            if client:
                client.update_last_seen()

            logging.info(f"Get Code: {code}")
            """Ensure that the actual payload size matches the declared size."""
            actual_payload_length = len(message) - constants.HEADER_LENGTH

            if actual_payload_length != payload_size:
                raise ValueError(f"Payload size mismatch. Declared: {payload_size}, Actual: {actual_payload_length}")

            # Route the message to the appropriate handler based on the request code
            handler = {
                constants.CODE_REGISTER: self.handle_registration,
                constants.CODE_SEND_PUBLIC_KEY: self.handle_public_key,
                constants.CODE_RECONNECT: self.handle_reconnect,
                constants.CODE_SEND_FILE: self.handle_send_file,
                constants.CRC_VALID_CODE: self.handle_crc_valid,
                constants.CRC_INVALID_CODE: self.crc_invalid_request,
                constants.FINAL_CRC_ERROR_CODE: self.final_crc_error
            }.get(code)

            if handler:
                handler(client_socket, message)
            else:
                raise ValueError(f"Invalid message code: {code}")

        except ValueError as e:
            self.handle_error(client_socket, f"Invalid message: {e}")

    # Handlers for different request codes
    def handle_registration(self, client_socket, message: bytes):
        """Handle client registration requests."""
        try:
            client_name = message[HEADER_SIZE:]  # extract client name
    
            # Ensure client_name is valid
            if (len(client_name) == 0 or client_name_exists(client_name)
                    or len(client_name) > constants.CLIENT_NAME_LEN):
                raise ValueError("Invalid client name.")

            client_id = uuid.uuid4().bytes  # Generate a UUID and convert to 16 byte

            if get_client(client_id) is not None:
                raise ValueError(f"Client with ID {client_id} is already registered.")

            add_client(client_id, client_name)

            # Send success response with client_id as payload
            res = Response.success_registration(client_id)  # Create a success response
            res.send(client_socket)  # Send the response

        except ValueError as e:
            res = Response(constants.RESPONSE_REGISTRATION_FAILED)
            res.send(client_socket)

    def handle_public_key(self, client_socket, message: bytes):
        """Handle public key reception from the client."""
        try:
            logging.info("Getting public key")
            client_id = message[:UUID_SIZE]
            public_key = self.helpers.extract_public_key(message)
            client_exists = get_client(client_id)

            if not client_exists:
                raise ValueError("Client not registered")

            # Generate AES key and encrypt with client's public key
            aes_key = get_random_bytes(AES_KEY_256)
            encrypted_aes_key = encryption_utils.encrypt_aes_key(public_key, aes_key)
            client_exists.public_key = public_key
            logging.info(f"Received public key from {client_id}")

            # Log the generated AES key in hex format (before encryption)
            logging.info(f"Generated AES Key (Server): {binascii.hexlify(aes_key).decode()}")
            client_exists.AES_key = aes_key
            logging.info(f"Encrypted AES Key (Server): {binascii.hexlify(encrypted_aes_key).decode()}")

            # Send the encrypted AES key to the client
            res = Response(constants.RESPONSE_AES_KEY_RECEIVED, client_id + encrypted_aes_key)
            res.send(client_socket)

        except ValueError as e:
            self.handle_error(client_socket, f"Public key error: {e}")
        except Exception as e:
            self.handle_error(client_socket, f"Unexpected error: {e}")

    def handle_reconnect(self, client_socket, message: bytes):
        """Handle client reconnection requests."""
        try:
            logging.info("Reconnect")
            client_id = ProtocolHandlerHelpers.extract_client_id(message)
            client_name = self.helpers.extract_payload(message)
            logging.info(f"Extracted client ID: {client_id.hex()}")
            client_exists = get_client(client_id)

            logging.info(f"client_exists in reconnect: {client_exists.client_id} {client_exists.public_key}")

            if not client_exists or not client_exists.public_key:
                add_client(client_id, client_name)
                res = Response(constants.RESPONSE_RECONNECT_FAILED, client_id)
                res.send(client_socket)
                return

            logging.info(f"client_exists in reconnect: {client_exists.client_id} {client_exists.public_key}")

            # Generate AES key and encrypt with client's public key
            aes_key = get_random_bytes(constants.AES_KEY_256)
            encrypted_aes_key = encryption_utils.encrypt_aes_key(client_exists.public_key, aes_key)
            client_exists.AES_key = aes_key

            # Send the encrypted AES key to the client
            res = Response(constants.RESPONSE_RECONNECT_SUCCESS, client_id + encrypted_aes_key)
            res.send(client_socket)

        except Exception as e:
            res = Response(constants.RESPONSE_RECONNECT_FAILED, client_id)
            res.send(client_socket)

    def send_crc_response(self, client_socket, client_id, content_size, file_name, crc):
        """Send CRC verification response to client."""
        content_size = struct.pack('<I', content_size)
        client_id = client_id.encode('utf-8') if isinstance(client_id, str) else client_id
        file_name = file_name.encode('utf-8')[:MAX_FILE_SIZE].ljust(255, b'\0')
        crc = struct.pack('<I', crc)
        res = Response(constants.RESPONSE_CRC_VERIFIED, client_id + content_size + file_name + crc)
        res.send(client_socket)

    def handle_send_file(self, client_socket, message: bytes):
        """Handle file transfer requests from the client."""
        try:
            client_id = message[:UUID_SIZE]
            logging.info(f"in send file, client id {client_id}")
            content_size, orig_file_size, packet_number, total_packets, file_name, file_content = (
                ProtocolHandlerHelpers.extract_file_info(message))

            # Validate content
            ProtocolHandlerHelpers.validate_content(orig_file_size, packet_number, total_packets, file_name)

            # Process client and save file chunk
            client_data = get_client(client_id)

            print_all_clients()

            if client_data is None:
                raise ValueError("Client not registered.")

            # Save the file chunk
            file_path = client_data.add_file_chunk(file_name, packet_number, total_packets, file_content)
            logging.info(f"Received packet {packet_number}/{total_packets} for file {file_name} from client {client_id.hex()} file path {file_path}.")

            if packet_number == total_packets and file_path is None:
                raise ValueError("File path is not valid.")

            # If this is the last packet, calculate CRC and send response
            if packet_number == total_packets and file_path:
                logging.info(f"File path: {file_path}")
                crc = ProtocolHandlerHelpers.calculate_crc(file_path)
                self.send_crc_response(client_socket, client_id, content_size, file_name, crc)

        except ValueError as e:
            self.handle_error(client_socket, f"File transfer error: {e}")
        except Exception as e:
            self.handle_error(client_socket, f"Unexpected error: {e}")

    def handle_crc_valid(self, client_socket, message: bytes):
        """Handle CRC validation requests for file verification."""
        try:
            file_name = self.helpers.extract_payload(message)
            logging.info(f"Performing CRC check for {file_name}")
            client_id = ProtocolHandlerHelpers.extract_client_id(message)
            res = Response(constants.MESSAGE_RECEIVED_RESPONSE, client_id)
            res.send(client_socket)
        except ValueError as e:
            self.handle_error(client_socket, f"CRC check error: {e}")

    def crc_invalid_request(self, client_socket, message: bytes):
        """Handle CRC validation requests for file verification."""
        try:
            client_id = ProtocolHandlerHelpers.extract_client_id(message)
            if get_client(client_id) is None:
                res = Response(constants.RESPONSE_UNKNOWN_ERROR)
                res.send(client_socket)

        except ValueError as e:
            self.handle_error(client_socket, f"CRC check error: {e}")

    def final_crc_error(self, client_socket, message: bytes):
        """Handle CRC validation requests for file verification."""
        try:
            file_name = self.helpers.extract_payload(message)
            logging.info(f"Performing CRC check for {file_name}")
            client_id = ProtocolHandlerHelpers.extract_client_id(message)
            res = Response(constants.MESSAGE_RECEIVED_RESPONSE, client_id)
            res.send(client_socket)
        except ValueError as e:
            self.handle_error(client_socket, f"CRC check error: {e}")

    def handle_error(self, client_socket, error_message):
        """Send an error response to the client."""
        # Log the error message
        logging.error(error_message)

        # Log the traceback to get more context about where the error occurred
        tb = traceback.format_exc()
        logging.error(tb)

        # Send the error message to the client (you might want to customize this)
        res = Response(constants.RESPONSE_UNKNOWN_ERROR)
        res.send(client_socket)
