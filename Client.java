import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
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
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Client {
	private String serverIP;
	private int serverPort;
	private String userID;

	private KeyFactory keyFactory;
	private PublicKey clientPub;
	private PrivateKey clientPrv;
	private PublicKey serverPub;

	public Client(String serverIP, int serverPort, String userID) {
		this.serverIP = serverIP;
		this.serverPort = serverPort;
		this.userID = userID;

		try {
			this.keyFactory = KeyFactory.getInstance("RSA");
			this.clientPub = loadPublicKey(userID + ".pub");
			this.clientPrv = loadPrivateKey(userID + ".prv");
			this.serverPub = loadPublicKey("server.pub");
			if (this.serverPub == null) {
				System.err.println(
						"Server's public key not found, therefore can't verify server's signature or send messages. Exiting the program...\n\n");
				System.exit(0);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		String serverIP = args[0];
		int serverPort = Integer.parseInt(args[1]);
		String userID = args[2];
		Client client = new Client(serverIP, serverPort, userID);
		client.start();
	}

	public void start() {
		Socket socket = null;
		DataOutputStream outputStream = null;
		DataInputStream inputStream = null;
		try {
			int receiveflag = 0;
			socket = new Socket(serverIP, serverPort);
			System.out.println("Connected to server");
			outputStream = new DataOutputStream(socket.getOutputStream());
			inputStream = new DataInputStream(socket.getInputStream());
			outputStream.writeUTF(computeUserIDMD5(userID));

			printAllMessagesToClient(inputStream);

			String sendString = "";
			String targetUserID = "";
			while (true) {
				System.out.println("Do you want to add a post? y/n");
				Scanner scanner = new Scanner(System.in);
				String input = scanner.nextLine();
				if (input.equals("y")) {
					System.out.println("Enter the recipient userid:");
					targetUserID = scanner.nextLine();
					System.out.println("Enter your message:");
					sendString = scanner.nextLine();
					// Identify whether the user is herself 
					if (this.userID.equals(targetUserID)) {
						System.out.println(
								"Please don't waste the server's resources, reconfirm whether you need to send a message or not.");
						sendString = "";
						targetUserID = "";
						continue;
					}
					sendString = targetUserID + ";;;" + sendString;
					byte[] encryptedMessage = encryptWithPublicKey(sendString.getBytes(), serverPub);

					String encodedEncryptedString = Base64.getEncoder().encodeToString(encryptedMessage);
					sendMessageToServer(encodedEncryptedString, outputStream);
					Instant instant = Instant.now();
					String output = instant.toString(); // Generates a String in standard ISO 8601 format.
					sendMessageToServer(output, outputStream);
					outputStream.writeUTF(userID);

					byte[] signature = createSignature(encryptedMessage, output);
					if (signature != null) {
						sendMessageToServer(Base64.getEncoder().encodeToString(signature), outputStream);
						System.out.println("The message is sent and the system closes automatically.");
					} else {
						System.err.println("Error sending the signature...");
					}
					TimeUnit.SECONDS.sleep(1);
					scanner.close();
					break;
				} else if (input.equals("n")) {
					System.out.println("system terminated");
					scanner.close();
					break;
				} else {
					System.out.println("The command you entered was not recognized, please try again.");
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			System.out.println(e.toString());
			throw new RuntimeException(e);
		} finally {
			try {
				inputStream.close();
				outputStream.close();
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void printAllMessagesToClient(DataInputStream inputStream) {
		String x = null;
		String y = null;
		String serverSignature = null;

		int numberOfMessages = 0;
		try {
			if ((numberOfMessages = inputStream.readInt()) != 0) {
				System.out.println("There are " + numberOfMessages + " message(s) for you.");
				for (int i = 0; i < numberOfMessages; i++) {
					x = inputStream.readUTF();
					y = inputStream.readUTF();
					serverSignature = inputStream.readUTF();
					if (checkSignature(x, serverSignature, y)) {
						System.out.println("The message is: "
								+ new String(decryptWithPrivateKey(Base64.getDecoder().decode(x), clientPrv), "UTF8"));
						System.out.println("The time of the message is: "
								+ ZonedDateTime.parse(y).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " UTC");
					}

				}
			}

		} catch (IOException e) {
			System.err.println("Server closed its connection.");
		}
	}

//Send the message to the server
	public void sendMessageToServer(String message, DataOutputStream outputStream) throws IOException {
		outputStream.writeUTF(message);
		outputStream.flush();
	}

//Calculates the md5 if user ID
	public String computeUserIDMD5(String UserID) throws NoSuchAlgorithmException {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte[] digest = md5.digest(("gfhk2024:" + UserID).getBytes());
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
	public PublicKey loadPublicKey(String filename) throws Exception {
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

	// Publickey encryption
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

	// Publickey decryption
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

	// Privatekey encryption
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

	// Privatekey decryption
	public static byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			System.err.println("error occurred while decrypt With Private Key: " + e.getMessage());
		}
		return null;
	}

	private boolean checkSignature(String userMessage, String serverSignature, String timeStamp) {

		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(serverPub);
			sig.update(userMessage.getBytes());
			sig.update(timeStamp.getBytes());
			return sig.verify(Base64.getDecoder().decode(serverSignature));

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			System.err.println("error occurred while check signature: " + e.getMessage());
			return false;
		}

	}

	private byte[] createSignature(byte[] encryptedMessage, String timeStamp) {
		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initSign(clientPrv);
			sig.update(encryptedMessage);
			sig.update(timeStamp.getBytes());
			byte[] signature = sig.sign();
			return signature;

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			System.err.println("error occurred while creating signature: " + e.getMessage());
		}
		return null;
	}
}
