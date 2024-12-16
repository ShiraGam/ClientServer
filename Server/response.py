from config import constants


class Response:
    def __init__(self, code:int, payload=None):
        if code <= 0:
            raise ValueError("Response code must be greater than zero")

        self.version = constants.RESPONSE_VERSION.to_bytes(1, 'little', signed=False)  # 1 byte unsigned
        self.code = code.to_bytes(2, 'little', signed=False)  # 2 bytes unsigned
        self.payload = payload.encode('utf-8') if isinstance(payload, str) else payload or b""
        self.payload_size = len(self.payload).to_bytes(4, 'little', signed=False)  # 4 bytes unsigned

    def get_response_bytes(self) -> bytes:
        """Return the complete response as bytes."""
        return self.version + self.code + self.payload_size + self.payload

    def send(self, client_socket):
        """Send the response to the client socket."""
        client_socket.sendall(self.get_response_bytes())

    @classmethod
    def success_registration(cls, client_id) :
        """Create a response indicating successful registration."""
        if len(client_id) != constants.CLIENT_ID_SIZE:  # Ensure client_id is exactly 16 bytes (128 bits)
            raise ValueError("Client ID must be 16 bytes.")

        payload = client_id  # Send client_id as the payload
        return cls(constants.RESPONSE_REGISTRATION_SUCCESS, payload)


