package NSM;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

public class NSMTrudy {
	static final int serverPort = 62156;
	
	private static PrintWriter ServerSocketWriter,ServerSocketWriter2;
	private static BufferedReader ServerSocketReader,ServerSocketReader2;
	private static Socket serverSocket,serverSocket2;
	
	public static void main(String[] args) {
		try {
			//Verify we have the stolen message as an argument
			if(args.length!=1){
				System.out.println("Invalid number of args");
				return;
			}
			
			//First socket that will be authenticated
			serverSocket = new Socket("localhost", serverPort);
			ServerSocketWriter = new PrintWriter(serverSocket.getOutputStream(), true);
			ServerSocketReader = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
			//Replay stolen message on first socket
			System.out.println("Replaying ticket and nonce:"+args[0]);
			ServerSocketWriter.println(args[0]);
			String authRequest=ServerSocketReader.readLine();
			byte[] authRequestBytes=DatatypeConverter.parseBase64Binary(authRequest);
			byte[] reflectionRequestNonce=Arrays.copyOfRange(authRequestBytes, 8, 16);
			System.out.println("Server reply to replayed message:"+authRequest);
			String[] stolenAuthRequestData=args[0].split(",");
			//Reflection socket that will be used to decrement requested nonce
			serverSocket2 = new Socket("localhost", serverPort);
			ServerSocketWriter2 = new PrintWriter(serverSocket2.getOutputStream(), true);
			ServerSocketReader2 = new BufferedReader(new InputStreamReader(serverSocket2.getInputStream()));
			//Send the nonce requested on the first socket
			System.out.println("Reflection attack to obtain requested nonce:"+stolenAuthRequestData[0]+","+DatatypeConverter.printBase64Binary(reflectionRequestNonce));
			ServerSocketWriter2.println(stolenAuthRequestData[0]+","+DatatypeConverter.printBase64Binary(reflectionRequestNonce));
			String auth2Response=ServerSocketReader2.readLine();
			System.out.println("Server reply with needed nonce:"+auth2Response);
			byte[] auth2ResponseBytes=DatatypeConverter.parseBase64Binary(auth2Response);
			//Send back the returned nonce from the second socket to the first socket
			System.out.println("Authentication completetion reply:"+DatatypeConverter.printBase64Binary(Arrays.copyOfRange(auth2ResponseBytes, 0, 8)));
			ServerSocketWriter.println(DatatypeConverter.printBase64Binary(Arrays.copyOfRange(auth2ResponseBytes, 0, 8)));
			
		}

		catch (Exception ex) {
			ex.printStackTrace();
		}
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
			if(serverSocket2!=null){
				try{
					serverSocket2.close();
					ServerSocketWriter2.close();
					ServerSocketReader2.close();
					
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	
}
