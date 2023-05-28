/**
 * SHA-3 derived functions and Keccak sponge for the purpose of implementing KMACXOF256
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */


import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Controller {
	
	static int choice;
	 public static void start(){
		 Console.printHeader();
		 while (true) {
			 Console.printMainScreen();
			 final String mainInput = Console.inputMain();
			 switch (mainInput) {
				 case "1":
					 System.out.println(">> Option 1:\"Generate a (Schnorr/DHIS) key pair\" selected");
					 choice = 1;
					 System.out.println("\n- Requirement 1: Password -");
					 options();
					 break;
				 case "2":
					 System.out.println(">> Option 2:\"Encrypt a given data file asymmetrically\" selected");
					 choice = 2;
					 System.out.println("\n- Requirement 1: Message -");
					 options();
					 break;
				 case "3":
					 System.out.println(">> Option 3:\"Decrypt a given data file asymmetrically\" selected"); 
					 decrypt();
					 break;
				 case "4":
					 System.out.println(">> Option 4:\"Generate a signature\" selected");
					 choice = 4;
					 System.out.println("\n- Requirement 1: Message -");
					 options();
					 break;
				 case "5":
					 System.out.println(">> Option 5:\"Verify a signature\" selected");
					 verify();
					 break;
				 case "6":
					 return;
			 }
			 System.out.println();
		 }
	 }
	 
	 public static void options(){
		 Console.printOptionScreen();
		 final String optionInput = Console.inputOption();
		 
	     switch (optionInput) {
            case "a":
                System.out.println(">> Option a:\"Enter a file\" selected");
                if(choice == 1) {
                	generateKeyPair(true);
                }else if(choice == 2) {
                	encryptUnderKey(true);
                }else if(choice == 4) {
                	generateSignature(true);
                }
                break;
            case "b":       
                System.out.println(">> Option b:\"Enter text directly\" selected");
                if(choice == 1) {
                	generateKeyPair(false);
                }else if(choice == 2) {
                	encryptUnderKey(false);
                }else if(choice == 4) {
                	generateSignature(false);
                }
                break;
        }
	 }
	 
	 public static void generateKeyPair(boolean file){ //1. Generate a (Schnorr/DHIS) key pair
		 String pw = null;
		 if (file) {
			 try {
				 String fileName = Console.getFileName();
				 pw = Files.readString(Paths.get(fileName));
			 } catch (IOException e) {
				 System.out.println("!The file does not exist!");
				 generateKeyPair(true);
			 }
		 }
		 else {
			pw = Console.getPassword();
		 }
		 
		 KeyPair key = SchnorrDHIES.keyPair(pw);
		 writeBytesPublicKey(key.publicKey.getBytes());
		 writeBytesPrivateKey(key.privateKey);
	 }
	 
	 public static void encryptUnderKey(boolean file){ //2. Encrypt a given data file under the(Schnorr/DHIES) public key
		 byte[] m = {};
		 byte[] kByte = {};
		 Ed448GPoint key = new Ed448GPoint();
		 
		 if (file) {
			 try {
				 String fileName = Console.getFileName();
				 m = Files.readAllBytes(Paths.get(fileName));
				 System.out.println("\n- Requirement 2: Key File -");
				 String fileNameKey = Console.getFileName();
				 kByte = Files.readAllBytes(Paths.get(fileNameKey));
				 key = Ed448GPoint.pointFromBytes(kByte);
			 } catch (IOException e) {
				 System.out.println("!The file does not exist!");
				 encryptUnderKey(true);
			 }
		 }
		 else {
			 m = Console.getText().getBytes();
			 System.out.println("\n- Requirement 2: Key File -");
			 String fileNameKey = Console.getFileName();
			 try {
				 kByte = Files.readAllBytes(Paths.get(fileNameKey));
				 key = Ed448GPoint.pointFromBytes(kByte);
			} catch (IOException e) {
				System.out.println("!The file does not exist!");
				encryptUnderKey(false);
			}
		 }
		 
		 byte [] mEncrypted = SchnorrDHIES.encrypt(m, key);
		 writeBytesEncrypted(mEncrypted);
	 }

	 public static void decrypt() { //3. Decrypt a given data file asymmetrically. 
		 byte[] m = {};
		 try {
			 System.out.println("\n- Requirement 1: Encrypted Message File -");
			 String fileName = Console.getFileName();
			 m = Files.readAllBytes(Paths.get(fileName));
		 } catch (IOException e) {
			 System.out.println("!The file does not exist!");
			 decrypt();
		 }
		 
		 System.out.println("\n- Requirement 2: Password -");
		 String pw = Console.getPassword();
		 byte[] decrypted = SchnorrDHIES.decrypt(m, pw); 
		 String s = new String(decrypted, StandardCharsets.UTF_8);
		 System.out.println(s);
	 }

	 public static void generateSignature(boolean file){ //4. Generate a signature
		 byte[] m = {};
		 if (file) {
			 try {
				 String fileName = Console.getFileName();
				 m = Files.readAllBytes(Paths.get(fileName));
			 } catch (IOException e) {
				 System.out.println("!The file does not exist!");
				 generateSignature(true);
			 }
		 }
		 else {
			 m = Console.getText().getBytes();
		 }
		 
		 System.out.println("\n- Requirement 2: Password -");
		 String pw = Console.getPassword();
		 byte[] signature = SchnorrDHIES.sign(m, pw); 
		 writeBytesSign(signature);
	 }
	 
	 
	 public static void verify(){ //5. Verify a signature
		 byte[] m = {};
		 byte[] signature = {};
		 byte[] kByte = {};
		 
		 Ed448GPoint v = new Ed448GPoint();
		 
		 try {
			 
			 System.out.println("\n- Requirement 1: Message File -");
			 String fileName = Console.getFileName();
			 m = Files.readAllBytes(Paths.get(fileName));
			 
			 System.out.println("\n- Requirement 2: Signature File -");
			 String fileNameSignature = Console.getFileName();
			 signature = Files.readAllBytes(Paths.get(fileNameSignature));
			 
			 System.out.println("\n- Requirement 3: Public Key File -");
			 String fileNamePublicKey = Console.getFileName();
			 kByte = Files.readAllBytes(Paths.get(fileNamePublicKey));
			 v = Ed448GPoint.pointFromBytes(kByte);
			 
		 } catch (IOException e) {
			 System.out.println("!The file does not exist!");
			 verify();
		 }

		 boolean verify = SchnorrDHIES.verify(signature, m, v);
		 
		 if(verify) {
			 System.out.println("It is a valid signature");
		 }else if(!verify) {
			 System.out.println("It is an invalid signature");
		 }
	 }
	 
	 private static void writeBytesPublicKey(byte[] bytes) {
		 try (FileOutputStream fos = new FileOutputStream("publicKey.txt")) {
			 fos.write(bytes);
		 }
		 catch (IOException ioe) { System.out.println("Could not write hash to file"); }
		 for (byte b : bytes) {
			 System.out.printf("%02X ", b);
		 }
		 System.out.println();
	 }
	 
	 private static void writeBytesPrivateKey(byte[] bytes) {
		 try (FileOutputStream fos = new FileOutputStream("privateKey.txt")) {
			 fos.write(bytes);
		 }
		 catch (IOException ioe) { System.out.println("Could not write hash to file"); }
		 for (byte b : bytes) {
			 System.out.printf("%02X ", b);
		 }
		 System.out.println();
	 }
	 
	 private static void writeBytesEncrypted(byte[] bytes) {
		 try (FileOutputStream fos = new FileOutputStream("encrypted.txt")) {
			 fos.write(bytes);
		 }
		 catch (IOException ioe) { System.out.println("Could not write hash to file"); }
		 for (byte b : bytes) {
			 System.out.printf("%02X ", b);
		 }
		 System.out.println();
	 }
	 
	 private static void writeBytesSign(byte[] bytes) {
		 try (FileOutputStream fos = new FileOutputStream("signature.txt")) {
			 fos.write(bytes);
		 }
		 catch (IOException ioe) { System.out.println("Could not write hash to file"); }
		 for (byte b : bytes) {
			 System.out.printf("%02X ", b);
		 }
		 System.out.println();
	 }
}
