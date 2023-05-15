/**
 * SHA-3 derived functions and Keccak sponge for the purpose of implementing KMACXOF256
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */


import java.util.*;

public class Console {
	private static final Scanner sc = new Scanner(System.in);

	public static void printHeader() {
		System.out.println("\n"
				+ "				  <Practical project - cryptographic library & app - part 1>						\n"
				+ "											  	 	 By Justin Goding, Andrew Lau, and Yeseong Jeon");

		System.out.println();
	}
	
	 public static void printMainScreen() {
	        System.out.println("Enter a number to choose an option below: ");
	        System.out.println("---------------------------------------------------------");
	        System.out.println("1. Compute a plain cryptographic hash");
	        System.out.println("2. Compute a MAC under a given passphrase");
	        System.out.println("3. Encrypt a given data file symmetrically");
	        System.out.println("4. Decrypt a given data file symmetrically");
		 	System.out.println("5. Exit");
	        System.out.println("---------------------------------------------------------");
	 }
	 
	 public static void printComputeOptionScreen() {
		 System.out.println();
		 System.out.println("Choose a computing option below: ");
		 System.out.println("----------------------");
		 System.out.println("a. Enter a file");
		 System.out.println("b. Enter text directly");
		 System.out.println("----------------------");
	 }
	 
	 public static String getFileName() {
		 System.out.println();
		 System.out.println("Please enter the name of the file below: ");
		 final String fileName = sc.next();
		 return fileName;
	 }
	 
	 public static String getText() {
		 System.out.println();
		 System.out.println("Please enter the text below: ");
		 final String text = sc.next();
		 return text;
	 }

	 public static String getPassword() {
		 System.out.println();
		 System.out.println("Please enter the Password below: ");
		 final String pw = sc.next();
		 return pw;
	 }
	 /**
	  * This function takes in a input from the user and checks if it is a valid input.
	  * If it is not, it will ask the user to input again.
	  *
	  * @return mainInput
	  */
	 public static String inputMain() {
		 String mainInput = sc.next();
		 final Set<String> set = new HashSet<>(Arrays.asList("1", "2", "3", "4", "5"));
		 while (!set.contains(mainInput)) {
			 System.out.println("!WRONG INPUT, TRY AGAIN by entering a number between 1 and 4!");
			 mainInput = sc.next();
		 }
		 return mainInput;
	 }

	 /**
	  * This function takes in a input from the user and checks if it is one of the options. 
	  * If it is not, it will ask the user to input again.
	  * 
	  * @return computeOptionInput
	  */
	 public static String inputComputeOption() {
		 String computeOptionInput = sc.next();
		 final Set<String> options = new HashSet<>(Arrays.asList("a", "b"));
		 while (!options.contains(computeOptionInput)) {
			 System.out.println("!WRONG INPUT, TRY AGAIN by entering a letter 'a' or 'b'");
			 computeOptionInput = sc.next();
		 }
		 return computeOptionInput;
	 }
	 
}
