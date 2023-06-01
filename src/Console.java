/**
 * Console code printing messages and receiving input
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 */

import java.util.*;

public class Console {
	private static final Scanner sc = new Scanner(System.in);

	public static void printHeader() {
		System.out.println("\n"
				+ "				  <Practical project - cryptographic library & app>						\n"
				+ "											  	 	 By Justin Goding, Andrew Lau, and Yeseong Jeon");

		System.out.println();
		System.out.println("Select app services:");
		System.out.println("---------------------------------------------------------");
		System.out.println("1. Symmetric Encryption with KMACXOF256");
		System.out.println("2. Asymmetric Encryption with DHIES and Schnorr signatures");
		System.out.println("3. Exit");
		System.out.println("---------------------------------------------------------");
	}

	public static void printMainScreenSymmetric() {
		System.out.println("Enter a number to choose an option below: ");
		System.out.println("---------------------------------------------------------");
		System.out.println("1. Compute a plain cryptographic hash");
		System.out.println("2. Compute a MAC under a given passphrase");
		System.out.println("3. Encrypt a given data file symmetrically");
		System.out.println("4. Decrypt a given data file symmetrically");
		System.out.println("5. Exit");
		System.out.println("---------------------------------------------------------");
	}
	
	 public static void printMainScreenAsymmetric() {
	        System.out.println("Enter a number to choose an option below: ");
	        System.out.println("---------------------------------------------------------");
	        System.out.println("1. Generate a (Schnorr/DHIES) key pair");
	        System.out.println("2. Encrypt a given data file or message");
	        System.out.println("3. Decrypt a given data file");
	        System.out.println("4. Generate a signature for a given data file or message");
		 	System.out.println("5. Verify a signature for a given data file");
			System.out.println("6. Exit");
	        System.out.println("---------------------------------------------------------");
	 }
	 
	 public static void printOptionScreen() {
		 System.out.println();
		 System.out.println("Choose a option below: ");
		 System.out.println("----------------------");
		 System.out.println("a. Enter a file");
		 System.out.println("b. Enter text directly");
		 System.out.println("----------------------");
	 }
	 
	 public static String getFileName() {
		 System.out.println();
		 System.out.println("Please enter the name of the file below: ");
		 final String fileName = sc.nextLine();
		 return fileName;
	 }
	 
	 public static String getText() {
		 System.out.println();
		 System.out.println("Please enter the text below: ");
		 final String text = sc.nextLine();
		 return text;
	 }

	 public static String getPassword() {
		 System.out.println();
		 System.out.println("Please enter the Password below: ");
		 final String pw = sc.nextLine();
		 return pw;
	 }
	 /**
	  * This function takes in a input from the user and checks if it is a valid input.
	  * If it is not, it will ask the user to input again.
	  *
	  * @return mainInput
	  */
	 public static String inputMain(int num) {
		 String mainInput = sc.nextLine();
		 final Set<String> set = new HashSet<>(Arrays.asList("1", "2", "3", "4", "5", "6"));
		 while (!set.contains(mainInput) || Integer.parseInt(mainInput) > num) {
			 System.out.println("Invalid input, please enter a number between 1 and " + num);
			 mainInput = sc.nextLine();
		 }
		 return mainInput;
	 }

	 /**
	  * This function takes in a input from the user and checks if it is one of the options. 
	  * If it is not, it will ask the user to input again.
	  * 
	  * @return computeOptionInput
	  */
	 public static String inputOption() {
		 String computeOptionInput = sc.nextLine();
		 final Set<String> options = new HashSet<>(Arrays.asList("a", "b"));
		 while (!options.contains(computeOptionInput)) {
			 System.out.println("!WRONG INPUT, TRY AGAIN by entering a letter 'a' or 'b'");
			 computeOptionInput = sc.nextLine();
		 }
		 return computeOptionInput;
	 }
	 
}
