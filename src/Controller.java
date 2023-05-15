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
					 System.out.println(">> Option 1:\"Compute a plain cryptographic hash\" selected");
					 choice = 1;
					 computeOption();
					 break;
				 case "2":
					 System.out.println(">> Option 2:\"Compute a MAC under a given passphrase\" selected");
					 choice = 2;
					 computeOption();
					 break;
				 case "3":
					 System.out.println(">> Option 3:\"Encrypt a given data file symmetrically\" selected");
					 encrypt();
					 break;
				 case "4":
					 System.out.println(">> Option 4:\"Decrypt a given data file symmetrically\" selected");
					 decrypt();
					 break;
				 case "5":
					 return;
			 }
			 System.out.println();
		 }
	 }
	 
	 public static void computeOption(){
		 Console.printComputeOptionScreen();
		 final String optionInput = Console.inputComputeOption();
		 
	     switch (optionInput) {
            case "a":
                System.out.println(">> Option a:\"Enter a file\" selected");
                if(choice == 1) {
                	computeTextPlain(true);
                }else if(choice == 2) {
                	computeMAC(true);
                }
                break;
            case "b":       
                System.out.println(">> Option b:\"Enter text directly\" selected");
                if(choice == 1) {
                	computeTextPlain(false);
                }else if(choice == 2) {
                	computeMAC(false);
                }
                break;
        }
	 }

	 public static void computeTextPlain(boolean file){ //Compute plain cryptographic hash of a text
		 byte[] m = {};
		 if (file) {
			 try {
				 String fileName = Console.getFileName();
				 m = Files.readAllBytes(Paths.get(fileName));
			 } catch (IOException e) {
				 System.out.println("!The file does not exist!");
				 computeTextPlain(true);
			 }
		 }
		 else {
			 m = Console.getText().getBytes();
		 }

		 byte[] hash = Main.KMACXOF256("".getBytes(), m, 512, "D".getBytes());
		 writeHash(hash);
	 }

	 private static void writeHash(byte[] hash) {
		 try (FileOutputStream fos = new FileOutputStream("encrypted.txt")) {
			 fos.write(hash);
		 }
		 catch (IOException ioe) { System.out.println("Could not write hash to file"); }
		 for (byte b : hash) {
			 System.out.printf("%02X ", b);
		 }
		 System.out.println();
	 }
	 
	 public static void computeMAC(boolean file){ //Compute a MAC of a text from a given file under a given passphrase
		 System.out.println("***chose number 2 insert file***");

		 byte[] m = {};
		 if (file) {
			 try {
				 String fileName = Console.getFileName();
				 m = Files.readAllBytes(Paths.get(fileName));
			 } catch (IOException e) {
				 System.out.println("!The file does not exist!");
				 computeMAC(true);
			 }
		 }
		 else {
			 m = Console.getText().getBytes();
		 }

		 String pw = Console.getPassword();

		 byte[] mac = Main.KMACXOF256(pw.getBytes(), m, 512, "T".getBytes());
		 writeHash(mac);
	 }

	 public static void encrypt() {
		 String inputFileName = Console.getFileName();
		 String pw = Console.getPassword();
		 try {
			byte[] m = Files.readAllBytes(Paths.get(inputFileName));
			SymmetricCryptogram crypt = Main.encryption(m, pw); // since xof has to return value, txt will contain nothing
			 try (FileOutputStream fos = new FileOutputStream("encrypted.txt")) {
				 fos.write(crypt.getZ());
				 fos.write(crypt.getC());
				 fos.write(crypt.getT());
			 }
		} catch (IOException e) {
			 System.out.println("!The file does not exist!");
			 encrypt();
		}
	 }
	 
	 public static void decrypt() {
		 // get the text from the input file
		 // let user to out pw through the console
		 // decrypt.
		 
		 String inputFileName = Console.getFileName();
		 String pw = Console.getPassword();
		 byte[] z;
		 byte[] c;
		 byte[] t;
		 byte[] m = {};
		 try {
			byte[] bytes = Files.readAllBytes(Paths.get(inputFileName));
			if (bytes.length > 128) {
				z = Arrays.copyOfRange(bytes, 0, 64);
				c = Arrays.copyOfRange(bytes, 64, bytes.length - 64);
				t = Arrays.copyOfRange(bytes, bytes.length - 64, bytes.length);
				m = Main.decrypt(z, c, t, pw.getBytes());
			}
			else {
				System.out.println("Given file does not contain a Symmetric Cryptogram");
				return;
			}

			if (m != null) {
				try (FileOutputStream fos = new FileOutputStream("decrypted.txt")) {
					fos.write(m);
				} catch (IOException ioe) {
					System.out.println("Could not write hash to file");
				}

				String s = new String(m, StandardCharsets.UTF_8);
				System.out.println(s);
			}

		} catch (IOException e) {
			System.out.println("!The file does not exist!");
		}
	 }
	 
}
