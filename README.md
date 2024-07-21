# Secure Server-Client Messaging System (Java, RSA Encryption)

This project implements a secure server-client messaging system in Java using RSA public-key cryptography and digital signatures.

Messages are:
- **Encrypted with the server's or recipient's public key**
- **Digitally signed by the sender**
- **Stored securely on the server**
- **Verified upon retrieval for authenticity and integrity**

## 📁 Folder Structure

```
project-root/
├── Server.java
├── Client.java
├── RSAKeyGen.java
├── server.pub              # Server's public key
├── server.prv              # Server's private key
├── <user>.pub              # Client public keys (e.g., alice.pub, bob.pub)
├── <user>.prv              # Client private keys (e.g., alice.prv, bob.prv)
```

> ⚠️ All `.pub` and `.prv` keys must be placed in the same directory as the `.java` files.

## 🛠 Requirements

- JDK 11 or above (no external dependencies required)

## 🔐 Key Generation

To generate RSA keys for server or clients:

```bash
javac RSAKeyGen.java
java RSAKeyGen <username>
```

This will produce:
- `<username>.pub`  Public Key
- `<username>.prv`  Private Key

> Example:
> ```bash
> java RSAKeyGen server
> java RSAKeyGen alice
> java RSAKeyGen bob
> ```

## 🚀 Running the Application

### 1. Start the Server

```bash
javac Server.java
java Server <port>
```

Example:

```bash
java Server 8888
```

### 2. Start a Client

```bash
javac Client.java
java Client <server_ip> <port> <userID>
```

Example:

```bash
java Client localhost 8888 alice
```

> The client will prompt whether to send a message or not. Messages are addressed to a recipient user ID and encrypted accordingly.

## 💡 How It Works

### 🔒 Encryption & Signatures

- The **client encrypts** the message with the **server’s public key**.
- A **digital signature** is created using the client’s private key and sent along with a timestamp.
- The server:
  - **Decrypts** the message using its private key.
  - **Validates** the client’s signature.
  - Re-encrypts the message using the **recipient's public key**.
  - Stores the encrypted message in memory, associated with the recipient.

### 📩 Message Retrieval

- When a client connects, the server checks if there are any messages for them (based on MD5 of their user ID).
- If found:
  - Each message is **sent in encrypted form**, along with the timestamp and server's digital signature.
  - The client decrypts the message and verifies the signature.

## ✅ Features

- End-to-end encrypted messaging
- Digital signature verification
- Timestamped messages
- Simple key file format
- In-memory message buffering
- MD5-based user identity mapping

## ⚠️ Limitations

- Messages are stored only **in-memory** (cleared on server restart).
- No authentication beyond MD5 hash of user ID.
- No persistent database or file-based storage.

## 📚 File Descriptions

| File           | Description                              |
|----------------|------------------------------------------|
| `Server.java`  | Main server logic, message routing       |
| `Client.java`  | Client-side logic, encryption/signature  |
| `RSAKeyGen.java` | Generates RSA key pairs for any user    |
| `<user>.pub`   | RSA public key for a given user          |
| `<user>.prv`   | RSA private key for a given user         |

## 📝 Example Run

```text
# On Server:
java Server 8888

# On Client (Alice):
java Client localhost 8888 alice

> Do you want to add a post? y/n
y
> Enter the recipient userid:
bob
> Enter your message:
Hello Bob!
```

## 📧 Message Flow

```
Alice ----(enc+sign)---> Server ----(verify)----> Bob
                        (re-encrypt for Bob)
```

## 🛡 Security Summary

| Feature                | Status       |
|------------------------|--------------|
| RSA encryption         | ✅ 2048-bit   |
| Digital signatures     | ✅ SHA-256    |
| Time-stamped messages  | ✅ ISO 8601   |
| MD5 user hashing       | ✅ With salt  |

## 📌 Notes

- Always generate keys with `RSAKeyGen.java` before starting.
- You can simulate multiple users by creating different key pairs and running multiple clients.
- This project is designed for educational use.

## 📄 License

This project code is for academic purposes only.
