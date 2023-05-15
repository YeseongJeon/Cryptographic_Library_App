/**
 * SHA-3 derived functions and Keccak sponge for the purpose of implementing KMACXOF256
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */

public class SymmetricCryptogram {
    private byte[] z;
    private byte[] c;
    private byte[] t;
    public SymmetricCryptogram(byte[] z, byte[] c, byte[] t){
        this.z = z;
        this.c = c;
        this.t = t;
    }

    public byte[] getZ() {
        return z;
    }

    public byte[] getC() {
        return c;
    }

    public byte[] getT() {
        return t;
    }
}
