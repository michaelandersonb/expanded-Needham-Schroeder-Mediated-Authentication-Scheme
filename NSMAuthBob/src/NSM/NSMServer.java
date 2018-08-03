package NSM;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;


public class NSMServer {

	private static final String KDCPassword = "Bob-KDCSufficientlyLongAndSecurePassword";
	static final int serverPort = 62156;
	private static ServerSocket serverSocket;
	private static SecretKeyFactory keyMaker;
	private static Cipher cipher;
	private static boolean extended,cbcMode;
	private static SecretKey KDCKey;
	private static SecureRandom random;
	private static byte[] IV;
	
	public static void main(String[] args) {
		String transformation;
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
			//Setup keys for reading ticket and encrypting nonce
			keyMaker=SecretKeyFactory.getInstance("DESede");
			random=new SecureRandom();
			DESedeKeySpec serverKeySpec = new DESedeKeySpec(KDCPassword.getBytes("UTF8"));
			KDCKey=keyMaker.generateSecret(serverKeySpec);
			cipher = Cipher.getInstance(transformation);
			serverSocket = new ServerSocket(serverPort);
					while(true)
					{
						//Listen for clients to authenticate
						Socket clientSocket = null;
						clientSocket = serverSocket.accept();
						new Thread(
							    new serverClientThread(
							        clientSocket)
							).start();
					}
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			if(serverSocket!=null)
			{
				try {
					serverSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				
			}
		}
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
	 * Get a 64 bit value to use as a nonce
	 * @return
	 */
	private static byte[] getNonce() {
		byte[] nonce = new byte[8];
		random.nextBytes(nonce);
		return nonce;
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
	
	private static class serverClientThread implements Runnable{
		
		private Socket clientSocket;
		private PrintWriter out;
		private BufferedReader in;
		private SecretKey clientKey;
		
		public serverClientThread(Socket clientSocket) {
			this.clientSocket=clientSocket;
		}

		public void run() {
			try
			{
				out = new PrintWriter(clientSocket.getOutputStream(), true);
				in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				//If using CBC wait for an IV
				if(cbcMode){
					IV=DatatypeConverter.parseBase64Binary(in.readLine());
				}
				
				byte[] expectedNonce=getNonce();
				//If using extended authentication create a nonce to send to the client for including in the ticket by KDC
				if(extended)
				{
					System.out.println("Decrypted ticket nonce:"+DatatypeConverter.printBase64Binary(expectedNonce));
					System.out.println("Encrypted ticket nonce:"+DatatypeConverter.printBase64Binary(encrypt(expectedNonce,KDCKey)));
					out.println(DatatypeConverter.printBase64Binary(encrypt(expectedNonce,KDCKey)));
				}
				//Read ticket and client nocnce
				String authRequest=in.readLine();
				String[] authRequestData=authRequest.split(",");
				if(authRequestData.length!=2)
				{
					throw new InvalidEncryptedDataException("Invalid server auth request");
				}
				System.out.println("Client auth request:"+authRequest);
				String decryptedTicket=decryptString(authRequestData[0], KDCKey);
				System.out.println("Decrypted ticket:"+decryptedTicket);
				String[] decryptedTicketData=decryptedTicket.split(",");
				//Verify the ticket is the proper format
				if(extended)
				{
					if(decryptedTicketData.length!=3)
					{
						throw new InvalidEncryptedDataException("Invalid server auth request");
					}
				}
				else
				{
					if(decryptedTicketData.length!=2)
					{
						throw new InvalidEncryptedDataException("Invalid server auth request");
					}
				}
				//Create the client key from the ticket
				DESedeKeySpec serverKeySpec = new DESedeKeySpec(DatatypeConverter.parseBase64Binary(decryptedTicketData[0]));
				clientKey=keyMaker.generateSecret(serverKeySpec);
				if(extended)
				{
					if(!Arrays.equals(DatatypeConverter.parseBase64Binary(decryptedTicketData[2]),expectedNonce))
					{
						throw new InvalidEncryptedDataException("Invalid server auth request");
					}
				}
				//Create a nonce for the client to decrypt and decrement to authenticate
				byte[] expectedReplyNonce = getNonce();
				
				byte[] decryptedReplyNonce = decrypt(DatatypeConverter.parseBase64Binary(authRequestData[1]),clientKey);
				System.out.println("Client sent:"+nonceToLong(decryptedReplyNonce));
				//Decrement the client's nonce for the reply
				decryptedReplyNonce=longToNonce(nonceToLong(decryptedReplyNonce)-1);
				System.out.println("Responding with expected client nonce:"+nonceToLong(decryptedReplyNonce));
				byte[] responseArray = new byte[16];
				System.out.println("Responding with expected server nonce:"+nonceToLong(expectedReplyNonce));
				System.arraycopy(decryptedReplyNonce, 0, responseArray, 0, 8);
				System.arraycopy(expectedReplyNonce, 0, responseArray, 8, 8);
				System.out.println("Decrypted auth response:"+DatatypeConverter.printBase64Binary(responseArray));
				//Encrypt and send both nonces
				out.println(DatatypeConverter.printBase64Binary(encrypt(responseArray,clientKey)));
				//Wait for client to send back decremented nonce
				String encryptedClientAuthReply=in.readLine();
				if(encryptedClientAuthReply!=null){
					//Verify the nonce has been properly decrmented
					byte[] decryptedClientAuthReply=decrypt(DatatypeConverter.parseBase64Binary(encryptedClientAuthReply), clientKey);
					System.out.println("Encrypted client reply:"+encryptedClientAuthReply);
					System.out.println("Client responded with:"+nonceToLong(decryptedClientAuthReply));
					if(!Arrays.equals(decryptedClientAuthReply, longToNonce(nonceToLong(expectedReplyNonce)-1)))
					{
						throw new InvalidEncryptedDataException("Invalid client auth reply");
					}
					//Authenticated successfully
					System.out.println("Authenticated Alice");
				}
			}
			catch(Exception ex)
			{
				ex.printStackTrace();
			}
			finally
			{
				if(clientSocket!=null)
				{
					try{
						clientSocket.close();
					}
					catch (IOException e) {
						e.printStackTrace();
					}
				}
				if(out!=null)
				{
					out.close();
				}
				try
				{
					if(in!=null)
					{
						in.close();
					}
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
			
		}
		
	}
	
}
