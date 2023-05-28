import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SchnorrDHIES {
    public static final Ed448GPoint G = new Ed448GPoint(new BigInteger("8"), true);

    /**
     * Generate an elliptic key pair from a given passphrase.
     * @param pw a given passphrase
     * @return a KeyPair with private key s and public key V
     */
    public static KeyPair keyPair(String pw) {
        // s <- KMACXOF256(pw, “”, 512, “SK”); s <- 4s
        byte[] s = KMACXOF256.KMACXOF256(pw.getBytes(), "".getBytes(), 512, "SK".getBytes());
        BigInteger S = new BigInteger(s).multiply(new BigInteger("4"));

        // V <- s*G
        Ed448GPoint V = G.multiply(S);

        // key pair: (s, V)
        return new KeyPair(s, V);
    }

    /**
     * Encrypt a message under a given public key.
     * @param m a given message
     * @param V a given public key
     * @return the encrypted message
     */
    public static byte[] encrypt(byte[] m, Ed448GPoint V) {
        // k <- Random(512); k <- 4k
        SecureRandom sr = new SecureRandom();
        byte[] k = new byte[64];
        sr.nextBytes(k);
        BigInteger K = new BigInteger(k).multiply(new BigInteger("4"));

        // W <- k*V; Z <- k*G
        Ed448GPoint W = V.multiply(K);
        Ed448GPoint Z = G.multiply(K);

        // (ka || ke) <- KMACXOF256(Wx, “”, 1024, “PK”)
        byte[] kake = KMACXOF256.KMACXOF256(W.x.toByteArray(), "".getBytes(), 1024, "PK".getBytes());
        byte[] ka = Arrays.copyOfRange(kake, 0, kake.length / 2);
        byte[] ke = Arrays.copyOfRange(kake, kake.length / 2, kake.length);

        // c <- KMACXOF256(ke, “”, |m|, “PKE”) ^ m
        byte[] c = KMACXOF256.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
        c = new BigInteger(c).xor(new BigInteger(m)).toByteArray();

        // t <- KMACXOF256(ka, m, 512, “PKA”)
        byte[] t = KMACXOF256.KMACXOF256(ka, m, 512, "PKA".getBytes());

        // cryptogram: (Z, c, t)
        byte[] cryptogram = Main.concat(Z.getBytes(), c);
        cryptogram = Main.concat(cryptogram, t);
        return cryptogram;
    }

    /**
     * Decrypt a given elliptic-encrypted cryptogram from a given password.
     * @param cryptogram a given elliptic-encrypted cryptogram
     * @param pw a given password
     * @return a decrypted message
     */
    public static byte[] decrypt(byte[] cryptogram, String pw) {
        byte[] z = Arrays.copyOfRange(cryptogram, 0, 58);
        byte[] c = Arrays.copyOfRange(cryptogram, 58, cryptogram.length - 64);
        byte[] t = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);
        Ed448GPoint Z = Ed448GPoint.pointFromBytes(z);

        // s <- KMACXOF256(pw, “”, 512, “SK”); s <- 4s
        byte[] s = KMACXOF256.KMACXOF256(pw.getBytes(), "".getBytes(), 512, "SK".getBytes());
        BigInteger S = new BigInteger(s).multiply(new BigInteger("4"));

        // W <- s*Z
        Ed448GPoint W = Z.multiply(S);

        // (ka || ke) <- KMACXOF256(Wx, “”, 1024, “PK”)
        byte[] kake = KMACXOF256.KMACXOF256(W.x.toByteArray(), "".getBytes(), 1024, "PK".getBytes());
        byte[] ka = Arrays.copyOfRange(kake, 0, kake.length / 2);
        byte[] ke = Arrays.copyOfRange(kake, kake.length / 2, kake.length);

        // m <- KMACXOF256(ke, “”, |c|, “PKE”) ^ c
        byte[] m = KMACXOF256.KMACXOF256(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
        m = new BigInteger(m).xor(new BigInteger(c)).toByteArray();

        // t’ <- KMACXOF256(ka, m, 512, “PKA”)
        byte[] tPrime = KMACXOF256.KMACXOF256(ka, m, 512, "PKA".getBytes());

        // accept if, and only if, t’ = t
        if (Arrays.equals(tPrime, t)) {
            return m;
        }
        else {
            System.out.println("Decryption unsuccessful: t' does not match t");
            return null;
        }
    }

    /**
     * Sign a given message from a given password.
     * @param m a given message
     * @param pw a given password
     * @return a signature
     */
    public static byte[] sign(byte[] m, String pw) {
        // s <- KMACXOF256(pw, “”, 512, “SK”); s <- 4s
        byte[] s = KMACXOF256.KMACXOF256(pw.getBytes(), "".getBytes(), 512, "SK".getBytes());
        BigInteger S = new BigInteger(s).multiply(new BigInteger("4"));

        //k <- KMACXOF256(s, m, 512, “N”); k <- 4k
        byte[] k = KMACXOF256.KMACXOF256(S.toByteArray(), m, 512, "N".getBytes());
        BigInteger K = new BigInteger(k).multiply(new BigInteger("4"));

        //U <- k*G;
        Ed448GPoint U = G.multiply(K);

        //h <- KMACXOF256(Ux, m, 512, “T”); z <- (k – hs) mod r
        byte[] h = KMACXOF256.KMACXOF256(U.x.toByteArray(), m, 512, "T".getBytes());
        BigInteger z = K.subtract(new BigInteger(h).multiply(S)).mod(Ed448GPoint.r);
        //signature: (h, z)
        return Main.concat(h, z.toByteArray());
    }

    /**
     * Verify a given message and its signature under a given public key
     * @param signature signature on the message
     * @param m a given message
     * @param V a given public key
     * @return True if the signature is valid, otherwise false
     */
    public static boolean verify(byte[] signature, byte[] m, Ed448GPoint V) {
        byte[] h = Arrays.copyOfRange(signature, 0, 64);
        byte[] z = Arrays.copyOfRange(signature, 64, signature.length);

        // U <- z*G + h*V
        Ed448GPoint U = G.multiply(new BigInteger(z)).add(V.multiply(H));

        // accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
        byte[] check = KMACXOF256.KMACXOF256(U.x.toByteArray(), m, 512, "T".getBytes());

        return Arrays.equals(h, check);
    }

}