/**
 * SHA-3 derived functions and Keccak sponge for the purpose of implementing KMACXOF256
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class Main {

    static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // Validity Conditions: Len(K) < 2^2040 and 0 <= L and Len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        SHAKE shake = new SHAKE();
        shake.kinit256(K, S);
        shake.update(X, X.length);
        shake.xof();
        shake.out(val, L >>> 3);

        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }

    private final static byte[] emptyBytes = {};

    public static SymmetricCryptogram encryption(byte[] m, String pw){
        SecureRandom random = new SecureRandom();
        /*z <- random(512) */
        byte[] z = new byte[64];
        random.nextBytes(z);

        /* (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”) */

        //z || pw
        byte[] zpw = SHAKE.concat(z, pw.getBytes());

        byte[] keka = KMACXOF256(zpw, emptyBytes, 1024, "S".getBytes());
        //ke
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        //ka
        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

        //c <- KMACXOF256(ke, “”, |m|, “SKE”) xor m
        byte[] c = KMACXOF256(ke, emptyBytes, m.length * 8, "SKE".getBytes());
        BigInteger cBigInt = new BigInteger(c);
        BigInteger mBigInt = new BigInteger(m);
        cBigInt = cBigInt.xor(mBigInt);
        c = cBigInt.toByteArray();

        //t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = KMACXOF256(ka, m, 512, "SKA".getBytes());

        return new SymmetricCryptogram(z,c,t);
    }


    public static byte[] decrypt(byte[] z, byte[] c, byte[] t, byte[] pw){
        //(ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] zpw = SHAKE.concat(z, pw);
        byte[] keka = KMACXOF256(zpw, emptyBytes, 1024, "S".getBytes());
        //ke
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        //ka
        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);


        // m <- KMACXOF256(ke, “”, |c|, “SKE”) xor c
        byte[] m = KMACXOF256(ke, emptyBytes, c.length * 8, "SKE".getBytes());
        BigInteger cBigInt = new BigInteger(c);
        BigInteger mBigInt = new BigInteger(m);
        mBigInt = mBigInt.xor(cBigInt);
        m = mBigInt.toByteArray();

        // t’ <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] tPrime = KMACXOF256(ka, m, 512, "SKA".getBytes());

        // accept if, and only if, t’ = t
        if(Arrays.equals(tPrime, t)) {
            return m;
        }else{
            System.out.println("Decryption unsuccessful: t' does not match t");
            return null;
        }
        
    }


    
    public static void main(String args[]) throws IOException {
        //Controller.start();
        Ed448GPoint G = new Ed448GPoint(new BigInteger("8"), true);
        if (G.isOnCurve()) {
            int passed = 0;
            int failed = 0;
            for (int i = 0; i < 100; i++) {
                Random rand = new Random();
                int k = rand.nextInt(Integer.MAX_VALUE);
                BigInteger K = new BigInteger(Integer.toString(k));
                int t = rand.nextInt(Integer.MAX_VALUE);
                BigInteger T = new BigInteger(Integer.toString(t));

                Ed448GPoint left = G.multiply(T).multiply(K);
                Ed448GPoint middle = G.multiply(K).multiply(T);
                Ed448GPoint right = G.multiply(K.multiply(T).mod(Ed448GPoint.r));
                if (left.equals(middle) && middle.equals(right)) {
                    passed++;
                } else {
                    failed++;
                }
            }
            System.out.println("All tests complete: " + passed + " passed, " + failed + " failed");
        }
    }
}

