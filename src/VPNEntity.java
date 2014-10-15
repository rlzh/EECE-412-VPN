import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.midi.Receiver;



public class VPNEntity {
		
	public enum InstanceType {
		Uninitialized,
		Client,
		Server,
	}
	
	public enum DataSendState {
		Encrypt,
		Sign,
		Send,
		Idle,
	}
	
	public enum DataReceiveState {
		Unsign,
		Decrypt,
		Idle,
	}
	
	public enum ConnectionState {
		Disconnected,
		Connected,
	}
	
	public String authConfirmation = "AUTHENTICATED";
	
	private InstanceType type = InstanceType.Uninitialized;
	private ConnectionState state = ConnectionState.Disconnected;
	// user input variables
	private String ip = null;
	private int port = -1;
	private String sharedSecret = null;
	
	// encryption and security variables
	private SecretKeySpec symmetricKey;
	private PublicKey otherPublicKey;
	private PublicKey myPublicKey;
	private PrivateKey myPrivateKey;
	private Cipher encryptCipher;
	private Cipher decryptCipher;
	
	// encryption and security constants
	private String cipherInstanceType = "AES/ECB/PKCS5Padding";
	private String signatureType = "SHA1withRSA";
	
	// connection variables
	protected Socket connection;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected String authString;
	// connection helper thread
	private ConnectionSetupHelper setupHelper;
	private Thread setupHelperThread;
	
	// step through send/receive variables
	public DataSendState dataSendState = DataSendState.Idle;
	public DataReceiveState dataReceiveState = DataReceiveState.Idle;
	public Boolean stepThroughReceive = false;
	private byte[] receivedBytes = new byte[0];
	
	public VPNEntity(InstanceType instanceType, String ipAddress, int portNumber, String sharedSecret) {
		this.type = instanceType;
		this.ip = ipAddress;
		this.port = portNumber;
		this.sharedSecret = sharedSecret;
	}
	
	/**
	 * Starts a new thread to set up network connection
	 * @throws IOException
	 */
	public void setupConnection() {
		this.setupHelperThread = new Thread(setupHelper);
		this.setupHelperThread.start();
	}
	
	/**
	 * Stops all threads and closes all connections 
	 * @throws IOException
	 */
	public void tearDownConnection() throws IOException {
		if(this.setupHelperThread != null) {
			System.out.println("Stopping setup helper thread");
			this.setupHelper.stopThread();
		}
		if(this.output != null) {
			System.out.println("Closing output");
			this.output.close();
		}
		if(this.input != null) {
			System.out.println("Closing input");
			this.input.close();
		}
		if(this.connection != null) {
			System.out.println("Closing connection");
			this.connection.close();
		}
		if(this.type == InstanceType.Server) {
			VPNServer server = (VPNServer) this;
			System.out.println("Closing server listener socket");
			if(server.getListenerSocket() != null)
				server.getListenerSocket().close();
		}
		System.out.println("connection torn down!");
	}
	
	/**
	 * Calculates symmetric key based on shared secret input and generates encrypt/decrypt ciphers
	 * Returns the symmetric key as string to be logged in ui
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public String calcSymmetricKey() throws NoSuchAlgorithmException, NoSuchPaddingException {
		// calculate the symmetric key
		this.symmetricKey = new SecretKeySpec(this.genMd5Hash().getBytes(), "AES");

		// generate encryption ciphers
		setupCiphers();

		return symmetricKey.toString();
	}
	
	/**
	 * Calculates random asymmetric keys to be used for signing and integrity protection
	 * Returns the key pair to be logged in ui
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public KeyPair calcAsymmetricKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		this.myPrivateKey = keyPair.getPrivate();
		this.myPublicKey = keyPair.getPublic();
		return keyPair;
	}
	
	/**
	 * Sends my public key to other end of connection to be used for integrity check
	 * @return
	 * @throws IOException
	 */
	public PublicKey sendPublicKey() throws IOException {
		output.writeObject(this.myPublicKey);
		output.flush();
		return this.myPublicKey;
	}
	
	/**
	 * Receives and stores public key from other end of connection to be use for integrity check
	 * @return
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	public PublicKey receivePublicKey() throws ClassNotFoundException, IOException {
		this.otherPublicKey = (PublicKey) input.readObject();
		return this.otherPublicKey;
	}
	
	/**
	 * Generates random session token to create auth challenge, then sends signed auth challenge
	 * @return
	 * @throws Exception
	 */
	public String sendAuthChallenge() throws Exception {
		
		// generate session token
		String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()";
		StringBuffer sb = new StringBuffer();
		Random rand = new Random();
		int length = rand.nextInt(20) + 10;
		for(int i = 0; i < length; i++ ) {
			int index = rand.nextInt(characters.length());
			char c = characters.charAt(index);
			sb.append(c);
		}
		
		// send session token 
		this.authString = sb.toString();
		byte[] data = authString.getBytes();
		
		// sign session token
		byte[] signedData = sign(data);
		
		sendMessage(signedData);
		
		return authString;
	}
	
	/**
	 * Returns encrypted & signed auth response of msg
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public byte[] sendAuthResponse(String msg) throws Exception {
		// encrypt auth response
		byte[] encryptedData = encryptText(msg);
		
		// sign auth response
		byte[] signedEncryptedData = sign(encryptedData);
		
		// send data
		sendMessage(signedEncryptedData);

		return signedEncryptedData;
	}
	
	/**
	 * Takes decrypted response and compares to see if it matches with auth token.
	 * Returns true if unsigned msg was valid and sends signed & encrypted auth confirmation, returns false otherwise
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public Boolean validateAuthResponse(String msg) throws Exception {
		StringBuilder sb = new StringBuilder();
		// append shared key to session token and set as authentication string to check response against
		sb.append(authString).append(sharedSecret);
		this.authString = sb.toString();
		
		if(msg.equals(authString)) {
			// sign and encrypt auth confirm data
			byte[] signedEncryptedAuthConfirmData = this.sign(encryptText(authConfirmation));
			// send data
			sendMessage(signedEncryptedAuthConfirmData);
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Sends byte array input across connection
	 * @param msg
	 * @return
	 * @throws Exception 
	 */
	public void sendMessage(byte[] msg) throws Exception {
		if(msg.length > 0) {
			output.writeInt(msg.length);
			output.write(msg, 0, msg.length);
			output.flush();
		}
	}
	
	/**
	 * Receives signed encrypted message across connection and returns as byte array
	 * @return
	 * @throws Exception
	 */
	public byte[] receiveMessage() throws Exception { 
		int msgLength = input.readInt();
		if(msgLength > 0) {
			byte[] data = new byte[msgLength];
			input.readFully(data);
			return data;
		}
		return new byte[0];
	}	
	
	/**
	 * Calculate the signature hash of message and signs message with my private key in format:
	 * [length of signature(first 4 bytes)| signature | original message]
	 * 
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public byte[] sign(byte[] msg) throws Exception {
        // Initialize a container for our signedMessage
        byte[] signedMessage = new byte[0];
 
        // Calculate the signature with an SHA1 hash function signed by the RSA private key
        Signature sig = Signature.getInstance(this.signatureType);
        sig.initSign(myPrivateKey);
        sig.update(msg);
        byte[] signature = sig.sign();
 
        // Add the length of the signature and the signature itself in front of the message
        signedMessage = concat(signedMessage,intToByteArray(signature.length));
        signedMessage = concat(signedMessage,signature);
 
        return concat(signedMessage, msg);
	}
	
	/**
	 * Determines hash sum of message with other public key and verify signature. If invalid, throws SignatureException.
	 * Else returns original message
	 * 
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public byte[] unsign(byte[] msg) throws Exception {
		// Read the signature from the signedMessage (and its length)
        int length = byteArrayToInt(Arrays.copyOf(msg,4));
        byte[] sentSignature = Arrays.copyOfRange(msg,4,4+length);
 
        // Determine the signed hash sum of the message
        byte[] message = Arrays.copyOfRange(msg, 4+length, msg.length);
        Signature sig = Signature.getInstance(this.signatureType);
        sig.initVerify(otherPublicKey);
        sig.update(message);
 
        // Verify the signature
        if (!sig.verify(sentSignature))
            throw new SignatureException("Signature invalid");
 
        return message;
	}
	
	/**
	 * Takes string input and returns encrypted byte array of input using symmetric key
	 * 
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public byte[] encryptText(String msg) throws Exception {
		
		encryptCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
	    cipherOutputStream.write(msg.getBytes());
	    cipherOutputStream.flush();
	    cipherOutputStream.close();
	    byte[] encryptedBytes = outputStream.toByteArray();
	    return encryptedBytes;
	    
	}
	
	/**
	 * Takes encrypted byte array input and returns decrypted String of input using symmetric key
	 * 
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public String decryptText(byte[] msg) throws Exception {

		decryptCipher.init(Cipher.DECRYPT_MODE, symmetricKey);
	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	    ByteArrayInputStream inStream = new ByteArrayInputStream(msg);
	    CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
	    byte[] buf = new byte[1024];
	    int bytesRead;
	    while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
	        outputStream.write(buf, 0, bytesRead);
	    }
	    return new String(outputStream.toByteArray());
	}
	
	
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	//	PRIVATE FUNCTIONS
	//
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	/**
	 * Generates symmetric ciphers for encrypting & decrypting
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	private void setupCiphers() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.encryptCipher = Cipher.getInstance(this.cipherInstanceType);
		this.decryptCipher = Cipher.getInstance(this.cipherInstanceType);
	}
	
	/**
	 * Generates 128-bit hash of shared secret input. Used to calculate symmetric key
	 * 
	 * @return
	 */
	private String genMd5Hash() {
		String digest = null;
		try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            //Add password bytes to digest
            md.update(sharedSecret.getBytes());
            //Get the hash's bytes
            byte[] bytes = md.digest();
            //This bytes[] has bytes in decimal format;
            //Convert it to hexadecimal format
            byte[] halfBytes = new byte[bytes.length / 2];
            for(int i = 0; i < halfBytes.length; i++) {
            	halfBytes[i] = (byte) (bytes[i] ^ bytes[i + halfBytes.length]);
            }
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< halfBytes.length ;i++)
            {
                sb.append(Integer.toString((halfBytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            //Get complete hashed password in hex format
            digest = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
		return digest;
	}
	
	/**
	 * Converts a int value into a byte array.
	 *
	 * @param value  int value to be converted
	 * @return  byte array containing the int value
	 */
	private byte[] intToByteArray(int value)
	{
	    byte[] data = new byte[4];
	 
	    // int -> byte[]
	    for (int i = 0; i < 4; ++i)
	    {
	        int shift = i << 3; // i * 8
	        data[3 - i] = (byte) ((value & (0xff << shift)) >>> shift);
	    }
	    return data;
	}
	 
	/**
	 * Converts a byte array to an int value.
	 *
	 * @param data  byte array to be converted
	 * @return  int value of the byte array
	 */
	private int byteArrayToInt(byte[] data)
	{
	    // byte[] -> int
	    int number = 0;
	    for (int i = 0; i < 4; ++i)
	    {
	        number |= (data[3-i] & 0xff) << (i << 3);
	    }
	    return number;
	}
	 
	/**
	 * Concatenates two byte arrays and returns the resulting byte array.
	 *
	 * @param a  first byte array
	 * @param b  second byte array
	 * @return  byte array containing first and second byte array
	 */
	private byte[] concat(byte[] a, byte[] b)
	{
	    byte[] c = new byte[a.length + b.length];
	    System.arraycopy(a, 0, c, 0, a.length);
	    System.arraycopy(b, 0, c, a.length, b.length);
	 
	    return c;
	}
	
	
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	//
	//	GETTER & SETTER FUNCTIONS
	//
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	public void setSetupHelper(ConnectionSetupHelper helper) {
		this.setupHelper = helper;
	}
	
	public void setConnection(Socket connection) {
		this.connection = connection;
	}
	
	public void setInputStream(ObjectInputStream input) {
		this.input = input;
	}
	
	public void setOutputStream(ObjectOutputStream output) {
		this.output = output;
	}
	
	public void setConnectionState(ConnectionState state) {
		this.state = state;
	}
	
	public void setReceivedBytes(byte[] b) {
		this.receivedBytes = b;
	}
	
	public Socket getConnection() {
		return this.connection;
	}
	
	public ObjectOutputStream getOutputStream() {
		return this.output;
	}
	
	public ObjectInputStream getInputStream() {
		return this.input;
	}
	
	public InstanceType getInstanceType() {
		return this.type;
	}
	
	public String getIp() {
		return this.ip;
	}
	
	public int getPortNumber() {
		return this.port;
	}
	
	public String getSharedSecret() {
		return this.sharedSecret;
	}
	
	public ConnectionState getConnectionState() {
		return this.state;
	}
	
	public byte[] getReceivedBytes() {
		return this.receivedBytes;
	}
}
