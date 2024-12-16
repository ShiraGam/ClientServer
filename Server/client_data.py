import struct
import re
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime
import logging

from config import constants


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# A dictionary to store the data of all clients
clients_data = {}

class ClientData:
    """Class that stores client information."""

    def __init__(self, client_id, client_name, public_key=None, AES_key=None):
        self.client_id = client_id
        self.client_name = client_name
        self.public_key = public_key
        self.AES_key = AES_key
        self.files = {}  # Dictionary to store file fragments with filename as key
        self.last_seen = datetime.now()

    def update_last_seen(self):
        """Update last seen time to the current time."""
        self.last_seen = datetime.now()

    def add_file_chunk(self, file_name, packet_number, total_packets, file_content):
        """Add a file chunk to the client's record after validation."""

        # Validate filename
        if not self.validate_filename(file_name):
            logging.warning(f"Invalid file name: {file_name}")
            raise ValueError(f"Invalid file name: {file_name}")

        logging.info(
            f"Adding chunk: file_name={file_name}, packet_number={packet_number}, total_packets={total_packets}")

        # Check if the file already exists
        if file_name in self.files:
            # If all packets have been received, reset for the new file
            if self.files[file_name]["received_packet_count"] == total_packets:
                logging.info(f"File {file_name} already exists and is complete. Resetting its record for a new upload.")
                self.files[file_name] = {
                    "total_packets": total_packets,
                    "received_packets": {},
                    "received_packet_count": 0,
                }

        else:
            # Initialize file record for a new file
            self.files[file_name] = {
                "total_packets": total_packets,
                "received_packets": {},
                "received_packet_count": 0,
            }

        # Only add the packet if it's not already received
        if packet_number not in self.files[file_name]["received_packets"]:
            self.files[file_name]["received_packets"][packet_number] = file_content
            self.files[file_name]["received_packet_count"] += 1

        # Check if all packets are received
        if self.files[file_name]["received_packet_count"] == total_packets:
            logging.info(f"All packets received for file: {file_name}.")
            file_path = self.assemble_file(file_name)
            return file_path

    @staticmethod
    def sanitize_filename(file_name):
        """Sanitize the filename to prevent directory traversal attacks."""
        # Allow only alphanumeric characters, underscores, dashes, and periods
        if not re.match(r'^[a-zA-Z0-9_\-.]+$', file_name):
            logging.warning("Invalid file name detected.")
            raise ValueError("Invalid file name detected.")
        return file_name

    def assemble_file(self, file_name):
        """Assemble file from all received packets, decrypt, and save to disk."""
        try:
            # Sanitize the filename
            if isinstance(file_name, bytes):
                file_name = file_name.decode('utf-8')
            file_name = self.sanitize_filename(file_name)

            # Sort packets and concatenate the content
            sorted_packets = sorted(self.files[file_name]["received_packets"].items())
            file_content = b''.join([packet[1] for packet in sorted_packets])

            # Decrypt the file content using AES key
            if self.AES_key is None:
                logging.warning("AES key not available for decryption.")
                raise ValueError("AES key not available for decryption.")

            cipher = AES.new(self.AES_key, AES.MODE_CBC, bytes([0] * AES.block_size))  # Ensure correct AES mode (CBC)
            decrypted_content = unpad(cipher.decrypt(file_content), AES.block_size)

            # Base directory where files are stored
            if isinstance(self.client_name, bytes):
                self.client_name = self.client_name.decode('utf-8')

            # Sanitize the client name by removing null characters
            self.client_name = self.client_name.replace('\0', '')

            base_directory = os.path.join(os.getcwd(), "client_files")  # Project directory
            directory = os.path.join(base_directory, self.client_name)

            logging.info(f"Creating directory: {directory} (base_directory: {base_directory})")

            # Ensure the directory exists
            os.makedirs(directory, exist_ok=True)

            # Handle absolute and relative paths
            if os.path.isabs(file_name):
                file_path = file_name  # Use the absolute path directly
            else:
                file_path = os.path.join(directory, file_name)  # Construct the relative path
            logging.info(f"File path: {file_path}")

            # Validate the final file path to prevent directory traversal
            if not os.path.commonprefix([file_path, os.path.abspath(directory)]) == os.path.abspath(directory):
                logging.warning(f"Invalid file path: {file_path}")
                raise ValueError("Invalid file path detected!")

            # Write the decrypted content to the file
            with open(file_path, "wb") as f:
                f.write(decrypted_content)  # Save decrypted content
            logging.info(f"Decrypted file {file_name} has been assembled and saved at {file_path}.")

            return file_path  # Return the file path
        except Exception as e:
            logging.error(f"Error while assembling file {file_name}: {e}")
            return None  # Optionally return None in case of an error

    def validate_filename(self, file_name):
        """Ensure the filename is valid (no special characters, appropriate length)."""
        if len(file_name) > 255:
            logging.warning(f"The length of the file name is too long: {len(file_name)}")
            return False
        # Regex to allow only alphanumeric characters, dashes, underscores, and periods
        return bool(re.match(r'^[a-zA-Z0-9_\-.]+$', file_name))


def add_client(client_id, client_name, public_key=None, AES_key=None):
    """Add a new client to the data structure, ensuring the client doesn't already exist."""
    if client_id in clients_data:
        raise ValueError(f"Client with ID {client_id} already exists.")
    clients_data[client_id] = ClientData(client_id, client_name, public_key, AES_key)


def get_client(client_id):
    """Retrieve client information by client ID."""
    return clients_data.get(client_id)


@staticmethod
def unpack_short(short_data):
    return struct.unpack("H", short_data)[0]


def decode_ascii(input_string):
    """Decode byte string as ASCII and strip null characters."""
    try:
        return input_string.decode('ascii').strip('\x00')
    except UnicodeDecodeError:
        raise ValueError("String is not valid ASCII.")

def print_all_clients():
    """Print information about all clients."""
    if not clients_data:
        logging.info("No clients found.")
        return

    logging.info("List of Clients:")
    for client_id, client_data in clients_data.items():
        logging.info(f"Client ID: {client_id}")
        logging.info(f"  Name: {client_data.client_name}")
        logging.info(f"  Public Key: {client_data.public_key}")
        logging.info(f"  AES Key: {client_data.AES_key}")
        logging.info(f"  Total Files: {len(client_data.files)}")
        logging.info(f"  Files: {list(client_data.files.keys())}")
        logging.info("")  # Blank line for better readability


@staticmethod
def client_name_exists(client_name):
    for client_data in clients_data.values():
        if client_data.client_name == client_name:
            return True
    return False
