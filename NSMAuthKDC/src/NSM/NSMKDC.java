package NSM;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class NSMKDC {
	
	private static final String alicePassword = "Alice-KDCSufficientlyLongAndSecurePassword";
	private static final String bobPassword = "Bob-KDCSufficientlyLongAndSecurePassword";
	private static final String aliceBobPassword= "Alice-BobSufficientlyLongAndSecurePassword";
	
	static final int KDCPort = 62155;
	private static ServerSocket KDCSocket;
	private static SecretKeyFactory keyMaker;
	private static Cipher cipher;
	private static HashMap<String,SecretKey> keyList;
	private static boolean extended,cbcMode;
	private static byte[] IV;
	
	static final int bobID = 1;
	static final int aliceID = 2;
	
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
			//Generate keys needed for communication
			DESedeKeySpec KDCKeySpec = new DESedeKeySpec(bobPassword.getBytes("UTF8"));
			keyMaker=SecretKeyFactory.getInstance("DESede");
			keyList=new HashMap<String,SecretKey>();
			keyList.put(bobID+"", keyMaker.generateSecret(KDCKeySpec));
			cipher = Cipher.getInstance(transformation);
			KDCSocket = new ServerSocket(KDCPort);
			while(true)
			{
				//Keep listening for connections
				Socket clientSocket = null;
				clientSocket = KDCSocket.accept();
				new Thread(
					    new KDCClientThread(
					        clientSocket, extended)
					).start();
			}
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			if(KDCSocket!=null)
			{
				try {
					KDCSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				
			}
		}
		
	}
	/**
	 * Converts the ascii string dataToDecrypt to bytes, encrypts and then returns the base64 of the encrypted bytes. pads the string so it is proper length
	 * @param dataToDecrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static String encrypt(String dataToEncrypt, SecretKey key)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		if (cbcMode) {
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
		}
		else{
			cipher.init(Cipher.ENCRYPT_MODE, key);
		}
		//Pad string
		int missingBytes=8-(dataToEncrypt.length()%8);
		for(int x=0; x<missingBytes;x++)
		{
			dataToEncrypt=dataToEncrypt+" ";
		}
		byte[] dataArray=dataToEncrypt.getBytes("US-ASCII");
		return DatatypeConverter.printBase64Binary(cipher.doFinal(dataArray));
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
	private static String decrypt(String dataToDecrypt, SecretKey key)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		if (cbcMode) {
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
		}
		else{
			cipher.init(Cipher.DECRYPT_MODE, key);
		}
		return DatatypeConverter.printBase64Binary(cipher.doFinal(DatatypeConverter.parseBase64Binary(dataToDecrypt)));
	}
	
	private static class KDCClientThread implements Runnable{
		
		private SecretKey clientKey;
		private PrintWriter out;
		private BufferedReader in;
		private Socket clientSocket;
		private boolean extendedNSM;
		
		public KDCClientThread(Socket clientSocket, boolean extendedNSM) {
			this.clientSocket=clientSocket;
			this.extendedNSM=extendedNSM;
		}

		public void run() {
			try
			{
				//Create variables needed for client communication
				out = new PrintWriter(clientSocket.getOutputStream(), true);
				in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				DESedeKeySpec KDCKeySpec = new DESedeKeySpec(alicePassword.getBytes("UTF8"));
				clientKey = keyMaker.generateSecret(KDCKeySpec);
				//Read IV if using CBC mode
				if(cbcMode){
					IV=DatatypeConverter.parseBase64Binary(in.readLine());
				}
				
				String clientRequest=in.readLine();
				System.out.println("Client request:"+clientRequest);
				String[] clientRequestData = clientRequest.split(",");
				String encryptedResponse;
				//If using extended then send back server nonce in ticket
				if(extendedNSM)
				{
					if(clientRequestData.length!=3)
					{
						throw new InvalidEncryptedDataException("Invalid client request");
					}
					String nonce1=clientRequestData[0];
					String clientID=clientRequestData[1];
					String encrytpedServerNonce=clientRequestData[2];
					
					SecretKey serverKey = keyList.get(clientID);
					
					String decryptedServerNocne=decrypt(encrytpedServerNonce, serverKey);
					
					DESedeKeySpec KABKeySpec = new DESedeKeySpec(aliceBobPassword.getBytes("UTF8"));
					System.out.println("Ticket to server:"+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+aliceID+","+decryptedServerNocne);
					String ticketToServer = encrypt(DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+aliceID+","+decryptedServerNocne,serverKey);
					System.out.println("Request reply:"+nonce1+","+bobID+","+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+ticketToServer);
					encryptedResponse = encrypt(nonce1+","+bobID+","+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+ticketToServer,clientKey);
				}
				//If using basic just send key and clientID
				else
				{
					if(clientRequestData.length!=2)
					{
						throw new InvalidEncryptedDataException("Invalid client request");
					}
					String nonce1=clientRequestData[0];
					String clientID=clientRequestData[1];
					
					SecretKey serverKey = keyList.get(clientID);
					
					DESedeKeySpec KABKeySpec = new DESedeKeySpec(aliceBobPassword.getBytes("UTF8"));
					System.out.println("Ticket to server:"+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+aliceID);
					String ticketToServer = encrypt(DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+aliceID,serverKey);
					System.out.println("Request reply:"+nonce1+","+bobID+","+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+ticketToServer);
					encryptedResponse = encrypt(nonce1+","+bobID+","+DatatypeConverter.printBase64Binary(KABKeySpec.getKey())+","+ticketToServer,clientKey);
				}
				out.println(encryptedResponse);
				
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
}
