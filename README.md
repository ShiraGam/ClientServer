# Encrypted File Transfer Client-Server System

## Overview

This project implements a client-server system for secure file transfers. 
The server is written in Python, and the client in C++. The client initiates a connection, exchanges encryption keys with the server, and securely transfers files.
This system also verifies file integrity and supports multi-client handling on the server side. 
Additionally, one of the objectives of the project was to analyze the protocol and identify potential vulnerabilities in its design.
**Note**: The system does not use SQL; therefore, the server does not persist data between runs.

## Architecture

- **Server**: Manages registered clients, handles file transfers, and maintains file integrity checks.
- **Client**: Registers with the server, establishes secure communication, and transfers files to the server.

## Requirements

- **Server**:
  - Python 3.12.1 or higher
  - `PyCryptodome` for encryption
- **Client**:
  - C++17
  - `Crypto++` library for encryption
  - Compatible with Visual Studio 2022

## Communication Protocol

- **Transport**: Binary protocol over TCP.
- **Encoding**: Little-endian unsigned integer values.
- **Request and Response Format**: Includes fields for version, request/response code, and payload size.

### Request Codes
- **825** - Register Client
- **826** - Send Public Key
- **827** - Reconnect
- **828** - Transfer Encrypted File
- **900** - Acknowledge CRC Success
- **901** - Acknowledge CRC Failure
- **902** - Final CRC Failure (Terminate)

### Response Codes
- **1600** - Registration Successful
- **1601** - Registration Failed
- **1602** - Public Key Received
- **1603** - File Transfer Success
- **1604** - Acknowledgment of Message
- **1605** - Reconnection Approved
- **1606** - Reconnection Denied
- **1607** - General Server Error

## Server

1. **Setup**:
   - Reads port from `port.info` (default: 1256 if not specified).
   - Waits for client requests in a loop.

2. **File Handling**:
   - Stores files in both memory and a local directory.
   - Checks file integrity using CRC.
   - **Note**: If a file with the same name already exists, it will be overwritten.

3. **Database**:
   - **Note**: No SQL database is used; client information is not persisted between runs.

## Client

1. **Configuration**:
   - Reads server IP and port from `transfer.info`.
   - Generates and stores a unique client ID and private key in `me.info`.

2. **Key Exchange**:
   - Generates RSA key pair, sends the public key to the server, and receives an AES key.

3. **File Transfer**:
   - Encrypts files using AES and sends them to the server in chunks.
   - Validates file integrity with CRC checks.

## Installation

1. **Server**:
   - Install Python 3.12.1+ and `PyCryptodome`.
   - Place `port.info` in the server directory with the desired port number.
   
2. **Client**:
   - Install Visual Studio 2022 and Crypto++.
   - Set up `transfer.info` with server IP, port, username, and file path.

## Execution

1. Start the server, which will wait for client connections.
2. Run the client, which will attempt to register, exchange keys, and transfer files.
3. On file transfer, both client and server will verify file integrity and retry if necessary.

## Error Handling

- **Client**: Retries sending data up to 3 times if errors occur, then exits with a detailed error message.
- **Server**: Manages unexpected errors gracefully and logs issues without crashing.





