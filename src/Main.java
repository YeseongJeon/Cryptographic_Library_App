/**
 * Application offering functionality for KMACXOF256 symmetric encryption and hashing
 * along with Schnorr/DHIES asymmetric encryption and signatures
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */

public class Main {

    public static void main(String[] args)  {
        boolean running = true;
        while (running) {
            Console.printHeader();
            final String mainInput = Console.inputMain(3);
            switch (mainInput) {
                case "1":
                    Symmetric.start();
                    break;
                case "2":
                    Asymmetric.start();
                    break;
                case "3":
                    running = false;
                    break;
            }
        }
    }

    public static byte[] concat(byte[] s1, byte[] s2){
        int s1Len = s1.length;
        int s2Len = s2.length;
        byte[] concatS = new byte[s1Len + s2Len];
        System.arraycopy(s1, 0, concatS,0, s1Len);
        System.arraycopy(s2, 0, concatS, s1Len, s2Len);
        return concatS;
    }
}

