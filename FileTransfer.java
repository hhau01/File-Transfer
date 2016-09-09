/*
** Henry Au
** CS380 - Project 8
** Due: Monday, March 14, 2016 before midnight (80 points)
** java FileTransfer makekeys
** java FileTransfer server private.bin 22222
** java FileTransfer client public.bin localhost 22222
**
** *NOTE* CANNOT DO CHUNKSIZE 1024 WITHOUT PADDING
*/

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.zip.CRC32;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.Math.*;

public final class FileTransfer{
	public static void main(String[] args) throws Exception{
		String mode = args[0];
		Cipher rsaCipher = Cipher.getInstance("RSA");
		Cipher aesCipher = Cipher.getInstance("AES");
		CRC32 crc = new CRC32();
		String outputFile = "test2.txt";

		switch(mode){
			//java FileTransfer makekeys
			//generate RSA key pair
			case "makekeys":
				try{
					KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
					gen.initialize(4096); //can use 2048 for faster key generation
					KeyPair keyPair = gen.genKeyPair();
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();
					try(ObjectOutputStream toPubFile = new ObjectOutputStream(
						new FileOutputStream(new File("public.bin")))){
						toPubFile.writeObject(publicKey);
					}
					try(ObjectOutputStream toPrvFile = new ObjectOutputStream(
						new FileOutputStream(new File("private.bin")))){
						toPrvFile.writeObject(privateKey);
					}
					catch(Exception e){
						e.printStackTrace(System.err);
					}
				}
				catch(Exception e){
					e.printStackTrace();
				}
				break;

			//java FileTransfer server private.bin 22222
			//server mode - second arg is name of file that contains private key
			//third arg is port number that server will listen on
			case "server":
				String prvKeyFile = args[1];
				int serverPort = Integer.parseInt(args[2]);
				//sequence number
				int s;
				long filesize = 0;
				int expSeq = 0;
				Object msg;
				int run = 1;
				int numChks = -1;

				try(ServerSocket serverSocket = new ServerSocket(serverPort)){
					while(true){
						//looking for client to connect
						Socket client = serverSocket.accept();

						ObjectInputStream sois = new ObjectInputStream(client.getInputStream());
						ObjectOutputStream soos = new ObjectOutputStream(client.getOutputStream());

						while(run == 1){
							//once connected get messages
							msg = sois.readObject();

							//close connection and wait for a new one
							if(msg instanceof DisconnectMessage){
								client.close();
								run = 0;
							}

							//prepare for file transfer based on info of msg
							//respond to client with AckMessage with seq num 0
							//if server is unable to begin file transfer respond with AckMessage with seq num -1
							
							//preparation for file transfer includes decrypting the session key passed by client
							//to do this, session key's serialized form was sent in StartMessage encrypted with
							//server's public key. server should decrypt this with its private key then deserialize
							//to an instance of Key. assume both sides use AES for symmetric encryption algorithm
							else if(msg instanceof StartMessage){
								StartMessage sm = (StartMessage)msg;
								filesize = sm.getSize();
								byte[] encKey = sm.getEncryptedKey();

								//get private key from bin file
								ObjectInputStream prvFile = new ObjectInputStream(new FileInputStream(prvKeyFile));
								PrivateKey prvKey = (PrivateKey)prvFile.readObject();
								
								try{
									rsaCipher.init(Cipher.DECRYPT_MODE,prvKey);
									byte[] decryptedSKey = rsaCipher.doFinal(encKey);
									s = 0;
									AckMessage start = new AckMessage(s);
									soos.writeObject(start);
									SecretKey skey = new SecretKeySpec(decryptedSKey,0,decryptedSKey.length,"AES");
									Key key = (Key)skey;

									//store session key
									ObjectOutputStream skFile = new ObjectOutputStream(new FileOutputStream(new File("skey.bin")));
									skFile.writeObject(key);
									
								}

								catch(Exception e){
									e.printStackTrace();
									s = -1;
									AckMessage unable = new AckMessage(s);
									soos.writeObject(unable);
								}
							}

							//server should discard associated file transfer and respond with AckMessage w/ seq num -1
							else if(msg instanceof StopMessage){
								s = -1;
								AckMessage stop = new AckMessage(s);
								soos.writeObject(stop);
							}

							//a)chunk's seq num must be the next expected seq num by the server
							//b)if so, decrypt data stored in the Chunk using session key from transfer initialization step
							//c)next, calculate CRC32 val for decrypted data and compare it with CRC32 val included in chunk
							//d)if CRC32 match and seq num of the chunk is the next expected seq num, the server should accept
							//	the Chunk by storing the data and incrementing the next expected seq num
							//e)the server should then respond with an AckMessage with seq num of the next expected Chunk
							else if(msg instanceof Chunk){
								Chunk chk = (Chunk)msg;
								int chunkseq = chk.getSeq();

								//if chunk seq is expected sequence
								if(chunkseq == expSeq){
									byte[] chkdata = chk.getData();

									//get private key from bin file
									ObjectInputStream getSKey = new ObjectInputStream(new FileInputStream("skey.bin"));
									Key thekey = (Key)getSKey.readObject();

									//decrypt using aes session key
						            aesCipher.init(Cipher.DECRYPT_MODE,thekey);
									byte[] decryptedChunk = rsaCipher.doFinal(chkdata);

									//crc checksum & compare
									crc.update(decryptedChunk);
					            	long chksum = crc.getValue();

					            	//if crc is correct, store in test2.txt
					            	if((int)chksum == chk.getCrc()){
					            		expSeq++;

					            		OutputStream fos;
					            		if(expSeq == 1){
					            			fos = new FileOutputStream(outputFile);
					            			fos.write(decryptedChunk);
					            		}

					            		else{
					            			fos = new FileOutputStream(outputFile,true);
					            			fos.write(decryptedChunk);
					            		}

					            		// String str = new String(decryptedChunk, "UTF-8");
					            		// //System.out.println(str);
					            		// PrintWriter storefile = new PrintWriter("test2.txt");
					            		// storefile.print(str);
					            		if(expSeq != numChks){
					            			int chksize = decryptedChunk.length;
					            			numChks = (int)Math.ceil(filesize/(double)chksize);
					            			//int numChks = (int)Math.ceil(filesize/(long)chksize);
					            		}
					            		System.out.println("Chunk received ["+expSeq+"/"+numChks+"].");

					            		AckMessage nxtSeq;
					            		if(expSeq < numChks){
					            			nxtSeq = new AckMessage(expSeq);
					            			soos.writeObject(nxtSeq);
					            		}
										
										else{
											System.out.println("Transfer complete.");
											System.out.println("Output path: " + outputFile + "\n");
											fos.close();
											
											nxtSeq = new AckMessage(expSeq);
					            			soos.writeObject(nxtSeq);
					            			numChks = -1;
					            			expSeq = 0;
										}					            		
					            	}
								}

								//respond with expected sequence num
								else{
									AckMessage eseq = new AckMessage(expSeq);
									soos.writeObject(eseq);
								}
							}

							else{ System.out.println("Error has occurred."); }
						}
					}
				}
				catch(Exception e){
					e.printStackTrace();
				}
				break;

			//java FileTransfer client public.bin localhost 22222
			//client mode - second arg is name of file that contains public key
			//third arg is the host to connect to where server is running
			//final arg is port number that server is listening to
			case "client":
				String pubKeyFile = args[1];
				String host = args[2];
				int port = Integer.parseInt(args[3]);
				int cont = 1;

				//connect to server
				Socket clientSocket = new Socket(host,port);
				System.out.println("Connected to server: " + host + "/" + clientSocket.getInetAddress().getHostAddress());

				//first generate AES session key
				// byte[] keyData = new byte[128];
				// SecureRandom sr = new SecureRandom();
				// sr.nextBytes(keyData);

				KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(128);
				SecretKey secretKey = keyGen.generateKey();

				//serialize the session key and store it in a byte array
				byte[] sessionKey = secretKey.getEncoded();

				//encrypt the serialized session key using the server's public key
				ObjectInputStream pubFile = new ObjectInputStream(new FileInputStream(pubKeyFile));
				PublicKey pubKey = (PublicKey)pubFile.readObject();
				
				rsaCipher.init(Cipher.ENCRYPT_MODE,pubKey);
				byte[] encryptedSKey = rsaCipher.doFinal(sessionKey);
				
				//prompt the user to enter the path for a file to transfer. file name? Ex: test.txt				
				Scanner clientInput = new Scanner(System.in);
				ObjectOutputStream coos = new ObjectOutputStream(clientSocket.getOutputStream());
				ObjectInputStream cois = new ObjectInputStream(clientSocket.getInputStream());

				while(cont == 1){
					boolean filefound = false;
					String filename = "";
					InputStream fis = null;

					while(!filefound){
						System.out.print("Enter path: ");
						filename = clientInput.nextLine();
						try{
							fis = new FileInputStream(filename);
							filefound = true;
						}
						
						catch(FileNotFoundException fnfe){
							System.out.println("Please enter valid filename.");
						}
					}

					//if path is valid, ask the user to enter the desired chunk size in bytes(default 1024 bytes)
					boolean validchunksize = false;
					String ci = "";
					int chunksize = 1024;
					while(!validchunksize){
						System.out.print("Enter chunk size[1024]: ");
						ci = clientInput.nextLine();
						try{
							chunksize = Integer.parseInt(ci);
							validchunksize = true;
						}

						catch(Exception e){
							System.out.println("Please enter valid integer.");
						}
					}
					
					//after accepting the path and chunk size, send the server a StartMessage that contains the file name,
					//	length of the file in bytes, chunk size, and encrypted session key
					//server should respond with an AckMessage with seq num 0 if the transfer can proceed,
					//	otherwise seq num will be -1
					StartMessage startMessage = new StartMessage(filename, encryptedSKey, chunksize);
					
					coos.writeObject(startMessage);

					
					Object response = cois.readObject();
					AckMessage ack = (AckMessage)response;
					int seq = ack.getSeq();

					//client should send ea Chunk of the file in order. after ea Chunk, wait for the server to respond with
					//	the appropriate AckMessage. the seq num in the ACK should be the num for the next expected Chunk
					//for ea Chunk, client must first read the data from the file and store it in an array based on chunk
					//	size. it should then calc CRC32 val for the chunk. finally, encrypt the chunk data using the session
					//	key. note that CRC32 val is for the plaintext of the chunk, not the ciphertext
					if(seq == 0){
						//get number of chunks
						long fsize = startMessage.getSize();
						int numChunks = (int)Math.ceil(fsize/(double)chunksize);
						//int numChunks = (int)Math.ceil(fsize/(long)chunksize);

						System.out.println("Sending: " + filename + ". File size: " + fsize + ".");
						System.out.println("Sending " + numChunks + " chunks.");

						byte[] fileinbytes = new byte[(int)fsize];
						;
						fis.read(fileinbytes);
						int count = 0;
						int chunknum = 1;

						//System.out.println(Arrays.toString(fileinbytes));

						// String str0 = new String(fileinbytes, "UTF-8");
						// System.out.println(str0);

						byte[] chunkydata = new byte[chunksize];

						//read in chunksize amount -> crc -> encrypt -> send
						for(int i = 0; i < fileinbytes.length; i++){
							chunkydata[i%(chunksize)] = fileinbytes[i];
							// String str1 = new String(chunkydata, "UTF-8");
							// System.out.println(str1);
							//if(i > 0 && i%chunksize == 0){
							if((i > 0 && i%(chunksize) == (chunksize-1)) || (i == fileinbytes.length-1)){
								byte[] chunkdata;
								if(chunknum == numChunks){
									chunkdata = Arrays.copyOf(chunkydata,i%chunksize+1);
								}

								else{
									chunkdata = Arrays.copyOf(chunkydata,chunkydata.length);
								}

								//System.out.println("Chunk " + chunknum + ": " + Arrays.toString(chunkdata) + "\n");
								// String str = new String(chunkdata, "UTF-8");
								// System.out.println(str);
								
								//calculate crc
					            crc.update(chunkdata);
					            long checksum = crc.getValue();
					            //System.out.println("Generated CRC32: " + (int)checksum + ".\n");

					            //encrypt using aes session key
					            aesCipher.init(Cipher.ENCRYPT_MODE,secretKey);
								byte[] encryptedChunk = rsaCipher.doFinal(chunkdata);

								//put into chunk message and send
								Chunk chunk = new Chunk(count,encryptedChunk,(int)checksum);
								coos.writeObject(chunk);
								System.out.println("Chunks completed ["+chunknum+"/"+numChunks+"].");
								fis.close();

								//receive acknowledgment
				            	response = cois.readObject();
								ack = (AckMessage)response;
								seq = ack.getSeq();

								//if seq = next chunk number send next chunk
								if(seq == (count+1)){
									count++;
									chunknum++;
								}
								else{
									i-=chunksize;
								}
							}
						}
					}

					//after sending all chunks and receiving the final ACK, transfer is complete and the client can either
					//	begin a new file transfer or disconnect
					System.out.println("\nWhat would you like to do?\n(1) Begin new file transfer\n(2) Disconnect");
					String choice = clientInput.nextLine();

					if(Integer.parseInt(choice) == 1){
						System.out.println();
					}

					else{
						cont = 0;
					 	DisconnectMessage dc = new DisconnectMessage();
					 	coos.writeObject(dc);
					}
				}
						
				break;
				

			default:
				System.out.println("First argument can only be 'makekeys', 'server', or 'client'.");
				break;

		}
	}
}