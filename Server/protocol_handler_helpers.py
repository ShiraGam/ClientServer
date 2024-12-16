import struct
from client_data import decode_ascii
import cksum
from config import constants
from config.constants import HEADER_SIZE, CLIENT_NAME_LEN, PUBLIC_KEY_LEN, HEADER_LENGTH, UUID_SIZE, MAX_FILE_SIZE, \
    FILE_CONTENT_OFFSET, FILENAME_OFFSET, TOTAL_PACKETS_OFFSET, PACKET_NUMBER_OFFSET, ORIG_FILE_SIZE_OFFSET, \
    DEFAULT_VERSION


class ProtocolHandlerHelpers:
    def __init__(self):
        pass

    @staticmethod
    def validate_message_length(message: bytes, expected_length):
        """Ensure that the message has at least the expected length."""
        if len(message) < expected_length:
            raise ValueError(f"Invalid message length. Expected at least {expected_length} bytes, got {len(message)}.")

    # Extractors for client data
    def extract_payload(self, message):
        """Extract and sanitize the client name from the message."""
        return message[HEADER_SIZE:]

    def extract_public_key(self, message):
        """Extract the public key from the message."""
        self.validate_message_length(message,HEADER_SIZE  + PUBLIC_KEY_LEN + CLIENT_NAME_LEN)  # Ensure enough length
        public_key = message[HEADER_SIZE + CLIENT_NAME_LEN :]
        return public_key

    def sanitize_string(self, input_string, max_length):
        """Sanitize and validate strings (e.g., client name)."""
        sanitized_string = decode_ascii(input_string)
        self.validate_string_length(sanitized_string, max_length)
        if not sanitized_string.isprintable():
            raise ValueError("String contains non-printable characters.")
        return sanitized_string

    @staticmethod
    def parse_header(message: bytes):
        """Parse and validate the message header (client_id, version, code, payload_size)."""

        if len(message) < HEADER_SIZE:
            raise ValueError(f"Message too short. Expected at least {HEADER_SIZE} bytes, got {len(message)}.")

        ProtocolHandlerHelpers.validate_message_length(message, HEADER_SIZE)

        client_id = ProtocolHandlerHelpers.extract_client_id(message)  # First 16 bytes for Client ID

        version = ProtocolHandlerHelpers.unpack_int(message[UUID_SIZE:UUID_SIZE+1])

        if version != DEFAULT_VERSION :
            raise ValueError(f"Invalid version: {version}")

        # Extract and validate code and payload_size
        code = ProtocolHandlerHelpers.unpack_int(message[17:19])

        payload_size = ProtocolHandlerHelpers.unpack_int(message[19:23])

        # Ensure that the payload size is within acceptable limits
        #if not (0 <= payload_size <= constants.MAX_PAYLOAD_SIZE):
            #raise ValueError(f"Invalid payload size: {payload_size}")

        return client_id, version, code, payload_size


    @staticmethod
    def validate_content(orig_file_size, packet_number, total_packets, file_name):
        """Validate the extracted content."""
        if orig_file_size > MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds limit of {MAX_FILE_SIZE} bytes.")
        if packet_number < 1 or packet_number > total_packets:
            raise ValueError(f"Invalid packet number: {packet_number}.")
        if not file_name:
            raise ValueError("File name is empty or invalid.")

    @staticmethod
    def extract_file_info(message: bytes):
        """Extract file-related information from the message."""
        content_size = ProtocolHandlerHelpers.unpack_int(message[HEADER_SIZE:ORIG_FILE_SIZE_OFFSET])
        orig_file_size = ProtocolHandlerHelpers.unpack_int(message[ORIG_FILE_SIZE_OFFSET:PACKET_NUMBER_OFFSET])
        packet_number = ProtocolHandlerHelpers.unpack_int(message[PACKET_NUMBER_OFFSET:TOTAL_PACKETS_OFFSET])
        total_packets = ProtocolHandlerHelpers.unpack_int(message[TOTAL_PACKETS_OFFSET:FILENAME_OFFSET])
        file_name = message[FILENAME_OFFSET:FILE_CONTENT_OFFSET].decode('utf-8').rstrip('\x00')
        file_content = message[FILE_CONTENT_OFFSET:]
        return content_size, orig_file_size, packet_number, total_packets, file_name, file_content

    @staticmethod
    def calculate_crc(file_path):
        """Calculate the CRC for the file."""
        with open(file_path, 'rb') as f:
            file_content = f.read()
        return cksum.memcrc(file_content)

    @staticmethod
    def validate_string_length(string, max_length):
        """Ensure the string does not exceed the maximum allowed length."""
        if len(string) > max_length:
            raise ValueError(f"String exceeds maximum length of {max_length} characters.")

    @staticmethod
    def extract_client_id(message):
        """Extract the Client ID from the message (first 16 bytes)."""
        ProtocolHandlerHelpers.validate_message_length(message, constants.CLIENT_ID_SIZE)
        return message[:UUID_SIZE]  # First 16 bytes are the Client ID


    @staticmethod
    def unpack_int(data: bytes) -> int:
        length = len(data)
        if length == 1:
            return struct.unpack('<B', data)[0]  # Unsigned char (1 byte)
        elif length == 2:
            return struct.unpack('<H', data)[0]  # Unsigned short (2 bytes)
        elif length == 4:
            return struct.unpack('<I', data)[0]  # Unsigned int (4 bytes)
        else:
            raise ValueError(f"Unsupported integer size: {length} bytes")
