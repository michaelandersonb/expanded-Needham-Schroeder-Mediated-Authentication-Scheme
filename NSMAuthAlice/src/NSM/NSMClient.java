package NSM;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class NSMClient {

	static final int serverPort = 62156;
	static final int KDCPort = 62155;

	static final int bobID = 1;
	static final String KDCPassword = "Alice-KDCSufficientlyLongAndSecurePassword";
	
	private static String transformation;
	private static SecureRandom random;
	private static Cipher cipher;
	private static SecretKey KDCkey, serverKey;
	private static SecretKeyFactory keyMaker;
	private static PrintWriter KDCSocketWriter,ServerSocketWriter;
	private static BufferedReader KDCSocketReader,ServerSocketReader;
	private static boolean extended,cbcMode;
	private static Socket serverSocket,KDCSocket;
	private static byte[] IV;
	public static void main(String[] args) {
		if(args.length!=2)
		{
			System.out.println("Invalid number of args");
			return;
		}
		if (args[0].equals("ecb")) {
			transformation = "DESede/ECB/Nopadding";
			cbcMode=false;
		} else if (args[0].equals("cbc")) {
			transformation = "DESede/CBC/Nopadding";
			cbcMode=true;
		} else {
			System.out.println("Invalid cipher");
			return;
		}
		if(args[1].equals("extended"))
		{
			extended=true;
		}
		else if (args[1].equals("basic"))
		{
			extended=false;
		}
		else
		{
			System.out.println("Invalid Needham-Schroeder mode");
			return;
		}
		try {
			//Setup variables needed for encryption and nonce generation
			random = new SecureRandom();
			DESedeKeySpec KDCKeySpec = new DESedeKeySpec(KDCPassword.getBytes("UTF8"));
			keyMaker = SecretKeyFactory.getInstance("DESede");
			KDCkey = keyMaker.generateSecret(KDCKeySpec);
			
			cipher = Cipher.getInstance(transformation);
			//Setup communication between KDC and server
			serverSocket = new Socket("localhost", serverPort);
			KDCSocket = new Socket("localhost", KDCPort);
			KDCSocketWriter = new PrintWriter(KDCSocket.getOutputStream(), true);
			KDCSocketReader = new BufferedReader(new InputStreamReader(KDCSocket.getInputStream()));
			ServerSocketWriter = new PrintWriter(serverSocket.getOutputStream(), true);
			ServerSocketReader = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
			//if CBC is used send IV to server and KDC
			if (cbcMode) {
				IV=getNonce();
				sendIV();
			}
			String encryptedServerNonce=null;
			//If using extended Needham-Schroeder get the nonce from the server
			if(extended)
			{
				encryptedServerNonce = getEncryptedServerNonce();
				System.out.println("Encrypted server nonce:"+encryptedServerNonce);
			}
			//Get ticket and encryption key from KDC
			String ticketToServer = requestTicketAndKey(bobID, encryptedServerNonce);
			//Send ticket and nonce to server
			byte[] nonce3=RequestServerAuth(ticketToServer);
			System.out.println("Authenticated Bob");
			//authenticat back to server
			authenticateToServer(nonce3);
		}

		catch (Exception ex) {
				ex.printStackTrace();
		}
		//Finally close anything we have open
		finally
		{
			if(serverSocket!=null){
				try{
					serverSocket.close();
					ServerSocketWriter.close();
					ServerSocketReader.close();
					
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
			if(KDCSocket!=null){
				try{
					KDCSocket.close();
					KDCSocketReader.close();
					KDCSocketWriter.close();
					
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Sends the 64bit IV to the server and KDC if using CBC
	 */
	private static void sendIV() {
		
		ServerSocketWriter.println(DatatypeConverter.printBase64Binary(IV));
		KDCSocketWriter.println(DatatypeConverter.printBase64Binary(IV));
	}

	/**
	 * send a nonce to the server that it is expecting
	 * @param nonce
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static void authenticateToServer(byte[] nonce) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		System.out.println("Responding with:"+(nonceToLong(nonce)-1));
		//Subtract from nonce, encrypt with server key and send back
		byte[] encryptedNonce3Response=encrypt(longToNonce((nonceToLong(nonce)-1)),serverKey);
		ServerSocketWriter.println(DatatypeConverter.printBase64Binary(encryptedNonce3Response));
	}

	private static String getEncryptedServerNonce() throws IOException {
		return ServerSocketReader.readLine();
	}

	/**
	 * Converts 64 bits to a long for purpose of decrementing
	 * @param nonce
	 * @return
	 */
	private static long nonceToLong(byte[] nonce)
	{
		long longNonce=0;
		for (int x = 0; x < nonce.length; x++)
		{
			longNonce = longNonce << 8 ;
			longNonce = longNonce + (nonce[x] & 0xff);
		}
		return longNonce;
	}
	
	/**
	 * converts long to 64bit byte array for sending back to server
	 * @param longNonce
	 * @return
	 */
	private static byte[] longToNonce(long longNonce)
	{
		return ByteBuffer.allocate(8).putLong(longNonce).array();
	}
	
	/**
	 * Sends the ticketToServer received from the KDC to the server and returns the decrypted nonce the server expects decremented.
	 * @param ticketToServer
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InvalidEncryptedDataException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static byte[] RequestServerAuth(String ticketToServer) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidEncryptedDataException, InvalidAlgorithmParameterException {
		//Make a nonce that we expect back
		byte[] nonce2 = getNonce();
		System.out.println("Decrypted nonce to server:"+nonceToLong(nonce2));
		//Encrypt our nonce
		String encryptedNonce2=DatatypeConverter.printBase64Binary(encrypt(nonce2,serverKey));
		System.out.println("Server Auth request:"+ticketToServer+","+encryptedNonce2);
		//Send ticket from KDC and nonce
		ServerSocketWriter.println(ticketToServer+","+encryptedNonce2);
		String encryptedServerAuthString=ServerSocketReader.readLine();
		System.out.println("Encrypted server auth response:"+encryptedServerAuthString);
		byte[] encryptedServerAuthBytes=DatatypeConverter.parseBase64Binary(encryptedServerAuthString);
		//Decrypt server response
		byte[] decryptedServerAuthBytes=decrypt(encryptedServerAuthBytes,serverKey);
		System.out.println("Decrypted server auth response:"+DatatypeConverter.printBase64Binary(decryptedServerAuthBytes));
		if(encryptedServerAuthBytes.length!=16)
		{
			throw new InvalidEncryptedDataException("Invalid server authentication response");
		}
		System.out.println("Server responseded with:"+nonceToLong(Arrays.copyOfRange(decryptedServerAuthBytes, 0, 8))+" and "+nonceToLong(Arrays.copyOfRange(decryptedServerAuthBytes, 8, 16)));
		byte[] responseNonce = Arrays.copyOfRange(decryptedServerAuthBytes, 0, 8);
		//Check if the server responded with the right nonce
		byte[] expectedResponseNonce = longToNonce(nonceToLong(nonce2)-1);
		
		if(!Arrays.equals(responseNonce,expectedResponseNonce))
		{
			throw new InvalidEncryptedDataException("Invalid server authentication response");
		}
		return Arrays.copyOfRange(decryptedServerAuthBytes, 8, 16);
	}

	/**
	 * Send a ticket and key request to KDC for clientID using the encryptedServerNonce receieved from the server
	 * @param clientID
	 * @param encryptedServerNonce
	 * @return
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidEncryptedDataException
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static String requestTicketAndKey(int clientID, String encryptedServerNonce)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidEncryptedDataException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		byte[] KDCNonce = getNonce();
		//If we are using extended mode then send the nonce to the KDC
		if(encryptedServerNonce!=null)
		{
			System.out.println("Request to KDC:"+DatatypeConverter.printBase64Binary(KDCNonce) + "," + bobID + "," + encryptedServerNonce);
			KDCSocketWriter.println(DatatypeConverter.printBase64Binary(KDCNonce) + "," + bobID + "," + encryptedServerNonce);
		}
		//If not using extended mode then just send ID and client nonce
		else
		{
			System.out.println("Request to KDC:"+DatatypeConverter.printBase64Binary(KDCNonce) + "," + bobID);
			KDCSocketWriter.println(DatatypeConverter.printBase64Binary(KDCNonce) + "," + bobID);
		}
		String encryptedTicketAndKeyString = KDCSocketReader.readLine();
		System.out.println("Encrypted ticket and key string:"+encryptedTicketAndKeyString);
		String decryptedTicketAndKeyString = decryptString(encryptedTicketAndKeyString, KDCkey);
		System.out.println("Decrypted ticket and key string:"+decryptedTicketAndKeyString);
		String[] ticketAndKeyData = decryptedTicketAndKeyString.split(",");
		
		if (ticketAndKeyData.length != 4) {
			throw new InvalidEncryptedDataException("Invalid response from KDC");
		}
		//Check if KDC gave correct nonce and client back 
		if ((!ticketAndKeyData[0].equals(DatatypeConverter.printBase64Binary(KDCNonce))) || (!ticketAndKeyData[1].equals(bobID + ""))) {
			throw new InvalidEncryptedDataException("Invalid response from KDC");
		}

		DESedeKeySpec serverKeySpec = new DESedeKeySpec(DatatypeConverter.parseBase64Binary(ticketAndKeyData[2]));
		serverKey = keyMaker.generateSecret(serverKeySpec);
		
		return ticketAndKeyData[3];
	}

	/**
	 * Get a 64 bit value to use as a nonce
	 * @return
	 */
	private static byte[] getNonce() {
		byte[] nonce = new byte[8];
		random.nextBytes(nonce);
		return nonce;
	}
	
	/**
	 * Encrypt the byte array using the given key and return the encrypted bytes
	 * @param dataToEncrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static byte[] encrypt(byte[] dataToEncrypt, SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		if (cbcMode) {
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
		}
		else{
			cipher.init(Cipher.ENCRYPT_MODE, key);
		}
		
		return cipher.doFinal(dataToEncrypt);
	}


	/**
	 * Converts the base64 string dataToDecrypt to bytes, decrypts and then returns the ascii of the decrypted bytes 
	 * @param dataToDecrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static String decryptString(String dataToDecrypt, SecretKey key)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		if (cbcMode) {
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
		}
		else{
			cipher.init(Cipher.DECRYPT_MODE, key);
		}
		return new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(dataToDecrypt)),"US-ASCII").trim();
	}

	/**
	 * Decrypt the dataToDecrypt bytes into it decrypted bytes
	 * @param dataToDecrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static byte[] decrypt(byte[] dataToDecrypt, SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		if (cbcMode) {
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
		}
		else{
			cipher.init(Cipher.DECRYPT_MODE, key);
		}
		return cipher.doFinal(dataToDecrypt);
	}
	
	/**
	 * Exception indicating that the encrypted data doesn't decrypt into the expected form.
	 * @author Michael
	 *
	 */
	static class InvalidEncryptedDataException extends Exception {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		public InvalidEncryptedDataException(String message) {
			super(message);
		}
	}

}
