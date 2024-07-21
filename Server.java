import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {

	private int port;
	private KeyFactory keyFactory;
	private PublicKey serverPub;
	private PublicKey receiverClientPub;
	private PublicKey senderClientPub;
	private String receiverClient;
	private String senderClient;
	private PrivateKey serverPrv;
	private Map<String, List<UserMessageBuffer>> userMessageBuffer;

	public Server(int port) {
		this.port = port;
		try {
			this.keyFactory = KeyFactory.getInstance("RSA");
			this.serverPub = loadPublicKey("server.pub");
			if (this.serverPub == null) {
				System.err.println(
						"Server's public key not found, therefore can't verify server's signature or send messages. Exiting the program...\n\n");
				System.exit(0);
			}
			this.serverPrv = loadPrivateKey("server.prv");
			if (this.serverPrv == null) {
				System.err.println(
						"Server's private key not found, therefore can't verify server's signature or send messages. Exiting the program...\n\n");
				System.exit(0);
			}
			userMessageBuffer = new HashMap<>();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws IOException {
		int port = Integer.parseInt(args[0]);
		Server server = new Server(port);
		server.start();
	}

	public void start() {
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(port);
			System.out.println("Server started on port " + port);
			while (true) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Client connected");
				DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream());
				DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream());
				String x = null, y = null;
				String userMessage = null;
				String userID = null;
				String timeStampString = null;
				byte[] encryptedMessage = null;
				try {
					if ((x = inputStream.readUTF()) != null) {
						userID = x;
						System.out.println("User ID: " + userID);

						sendAllMessagesToClient(outputStream, userID);

						if ((x = inputStream.readUTF()) != null) {
							encryptedMessage = Base64.getDecoder().decode(x);
							userMessage = new String(decryptWithPrivateKey(encryptedMessage, serverPrv), "UTF8");
							String[] parts = userMessage.split(";;;");
							receiverClient = parts[0];
							receiverClientPub = loadPublicKey(receiverClient + ".pub");
							if (receiverClientPub != null) {
								String encodedEncryptedString = Base64.getEncoder()
										.encodeToString(encryptWithPublicKey(parts[1].getBytes(), receiverClientPub));

								if ((y = inputStream.readUTF()) != null) {
									timeStampString = y;

								}
								if ((y = inputStream.readUTF()) != null) {
									senderClient = y;
									senderClientPub = loadPublicKey(y + ".pub");
								}
								if ((x = inputStream.readUTF()) != null && senderClientPub != null) {
									if (checkSignature(encryptedMessage, x, timeStampString)) {
										System.out.println("Signature verified");
										List<UserMessageBuffer> userMessages = new ArrayList<>();
										// ... add messages to userMessages ...
										userMessages
												.add(new UserMessageBuffer(encodedEncryptedString, timeStampString));
										userMessageBuffer.put(computeUserIDMD5(receiverClient), userMessages);
										System.out.println("Recipient:- " + receiverClient);
										System.out.println("Message:- " + parts[1]);
										System.out.println("Time:- " + 
												ZonedDateTime.parse(timeStampString).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " UTC");
									} else
										System.out.println("Signature not verified");

								}
							}

						}

					}

				} catch (IOException e) {
					System.err.println("Client closed its connection.");
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			try {
				serverSocket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void sendAllMessagesToClient(DataOutputStream outputStream, String userID) {
		try {
			List<UserMessageBuffer> messages = userMessageBuffer.get(userID);
			if (messages != null) {
				outputStream.writeInt(messages.size());
				System.out.println("delivering " + messages.size() + " message(s)...");
				for (UserMessageBuffer message : messages) {
					sendMessageToClient(message.getMessageContent(), outputStream);
					sendMessageToClient(message.getMessageTime(), outputStream);
					sendMessageToClient(
							Base64.getEncoder().encodeToString(
									createSignature(message.getMessageContent(), message.getMessageTime())),
							outputStream);
				}
			} else {
				outputStream.writeInt(0);
				System.out.println("delivering 0 message(s)...");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private boolean checkSignature(byte[] userMessage, String clientSignature, String timeStamp) {
		System.out.println("Arrived for signature");
		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(senderClientPub);
			sig.update(userMessage);
			sig.update(timeStamp.getBytes());
			return sig.verify(Base64.getDecoder().decode(clientSignature));

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			System.err.println("error occurred while check Signature: " + e.getMessage());
			return false;
		}

	}

	private byte[] createSignature(String encodedEncryptedString, String timeStamp) {
		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initSign(serverPrv);
			sig.update(encodedEncryptedString.getBytes());
			sig.update(timeStamp.getBytes());
			byte[] signature = sig.sign();
			return signature;

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			System.err.println("error occurred while create Signature: " + e.getMessage());
		}
		return null;
	}

	public void handleOnClose(ByteArrayOutputStream buffer, InputStream inputStream, OutputStream outputStream,
			Socket clientSocket) throws IOException {
		buffer.close();
		inputStream.close();
		outputStream.close();
		clientSocket.close();
	}

	// Calculate md5 of user id
	public String computeUserIDMD5(String UserID) throws NoSuchAlgorithmException {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte[] digest = md5.digest(("gfhk2024:" + UserID).getBytes());
		// Calculate hexadecimal byte array
		String userID_MD5 = getHexStringFromBytes(digest);
		return userID_MD5;
	}

	private String getHexStringFromBytes(byte[] byteArray) {
		StringBuilder hexBuilder = new StringBuilder();
		for (byte bd : byteArray) {
			hexBuilder.append(String.format("%02X", bd));
		}
		return hexBuilder.toString();
	}

	// For loading public keys
	public PublicKey loadPublicKey(String filename) {
		try {
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Files.readAllBytes(new File(filename).toPath()));
			return keyFactory.generatePublic(publicSpec);
		} catch (IOException | InvalidKeySpecException e) {
			System.err.println("Public Key file not found: " + e.getMessage());
		}
		return null;

	}

	// For loading private keys
	public PrivateKey loadPrivateKey(String filename) throws Exception {
		try {
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(Files.readAllBytes(new File(filename).toPath()));
			return keyFactory.generatePrivate(privateSpec);
		} catch (IOException | InvalidKeySpecException e) {
			System.err.println("Private Key file not found: " + e.getMessage());
		}
		return null;
	}

	// Public key encryption
	public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			System.err.println("error occurred while encrypt With PublicKey: " + e.getMessage());
		}
		return null;
	}

	// Public key decryption
	public static byte[] decryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			System.err.println("error occurred while decrypt With PublicKey: " + e.getMessage());
		}
		return null;
	}

	// Private key decryption
	public static byte[] encryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			System.err.println("error occurred while encrypt With PrivateKey: " + e.getMessage());
		}
		return null;
	}

	// Private key decryption
	public static byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			System.err.println("error occurred while decrypt With PrivateKey: " + e.getMessage());
		}
		return null;
	}

	public void sendMessageToClient(String message, DataOutputStream outputStream) throws IOException {
		outputStream.writeUTF(message);
		outputStream.flush();
	}

	public class UserMessageBuffer {
		String messageContent;
		String messageTime;

		public UserMessageBuffer(String userMessage, String timeStampString) {
			this.messageContent = userMessage;
			this.messageTime = timeStampString;
		}

		public String getMessageContent() {
			return messageContent;
		}

		public void setMessageContent(String messageContent) {
			this.messageContent = messageContent;
		}

		public String getMessageTime() {
			return messageTime;
		}

		public void setMessageTime(String messageTime) {
			this.messageTime = messageTime;
		}

		@Override
		public String toString() {
			return "UserMessageBuffer [messageContent=" + messageContent + ", messageTime=" + messageTime + "]";
		}
	}
}
