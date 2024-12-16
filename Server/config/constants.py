# Versioning
DEFAULT_VERSION = 3
RESPONSE_VERSION = 3

# Response Codes
RESPONSE_REGISTRATION_SUCCESS = 1600
RESPONSE_REGISTRATION_FAILED = 1601
RESPONSE_AES_KEY_RECEIVED = 1602
RESPONSE_CRC_VERIFIED = 1603
MESSAGE_RECEIVED_RESPONSE = 1604
RESPONSE_RECONNECT_SUCCESS = 1605
RESPONSE_RECONNECT_FAILED = 1606
RESPONSE_UNKNOWN_ERROR = 1607

# General constants
VERSION_SIZE = 1
CLIENT_ID_SIZE = 16  # Size in bytes
CODE_SIZE = 2  # Code field size in bytes
PAYLOAD_SIZE_BYTES = 4  # Payload size field size in bytes
PUBLIC_KEY_LEN = 160# Define the length of the public key in bytes
CLIENT_NAME_LEN =255
PUBLIC_KEY_OFFSET = 278  # Offset where the public key starts in the message
MAX_CONNECTIONS = 25
MAX_PORT = 65535

CODE_REGISTER = 825
CODE_SEND_PUBLIC_KEY = 826
CODE_RECONNECT = 827
CODE_SEND_FILE = 828
CRC_VALID_CODE = 900
CRC_INVALID_CODE = 901
FINAL_CRC_ERROR_CODE = 902

MAX_CLIENT_NAME_LEN = 255
MAX_PAYLOAD_SIZE =  10 * 1024 *1024

HEADER_LENGTH = 23  # Fixed header size

HEADER_SIZE = 23
UUID_SIZE = 16
MAX_FILE_SIZE =255

AES_KEY_256 = 32

# File information offsets
ORIG_FILE_SIZE_OFFSET = 27
PACKET_NUMBER_OFFSET = 31
TOTAL_PACKETS_OFFSET = 33
FILENAME_OFFSET = 35         # File name length in message
FILE_CONTENT_OFFSET = 290     # Offset where file content starts


DEFAULT_PORT = 1256
