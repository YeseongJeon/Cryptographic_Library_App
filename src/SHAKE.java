/**
 * SHA-3 derived functions and Keccak sponge for the purpose of implementing KMACXOF256
 * @author Justin Goding, Yeseong Jeon, Andrew Lau
 * Some code borrowed from/inspired by Markku-Juhani Saarinen's C implementation of SHA-3
 * functions at https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * Some code borrowed from Professor Paulo Barreto
 */

import java.nio.ByteBuffer;


public class SHAKE {

    private boolean ext;
    private boolean kmac;
    private byte[] b;
    private int pt;
    private int rsiz;

    static final public byte[] right_encode_0 = {(byte)0x00, (byte)0x01};
    static final public int KECCAKF_ROUNDS = 24;

    private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    static final public int[] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    static final public int[] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    public SHAKE() {
        ext = false;
        kmac = false;
        b = new byte[200];
        pt = 0;
        rsiz = 0;
    }

    public void kinit256(byte[] K, byte[] S) {
        this.ext = true;
        this.kmac = true;
        this.rsiz = 136;
        this.pt = 0;

        byte[] NS = Main.concat(encode_string("KMAC".getBytes()), encode_string(S));
        NS = bytepad(NS, 136);
        update(NS, NS.length);

        byte[] new_k = bytepad(encode_string(K), 136);
        update(new_k, new_k.length);

    }

    public void update(byte[] X, int len) {
        int j = this.pt;
        for (int i = 0; i < len; i++) {
            this.b[j++] ^= X[i];
            if (j >= this.rsiz) {
                sha3_keccakf(this.b);
                j = 0;
            }
        }
        this.pt = j;
    }

    public void out(byte[] val, int L) {
        int j = this.pt;
        for (int i = 0; i < L; i++) {
            if (j >= this.rsiz) {
                sha3_keccakf(this.b);
                j = 0;
            }
            val[i] = this.b[j++];
        }
        this.pt = j;
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    private static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || X
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)];
        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        // 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while (len(z)/8 mod w != 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        // 4. return z
        return z;
    }

    public static byte[] right_encode(long x) {
        // Validity Conditions: 0 ≤ x < 2^2040
        assert x >= 0;
        assert x <= Math.pow(2, 2040);
        // 1. Let n be the smallest positive integer for which 2^8n > x.
        int n = 1;
        while (Math.pow(2, 8 * n) <= x) {
            n++;
        }
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x satisfying:
        //      x = ∑ 2^(8(n-i)) * xi, for i = 1 to n.
        ByteBuffer b = ByteBuffer.allocate(n + 1);
        // 3. Let Oi = enc8(xi), for i = 1 to n.
        for (int i = 0; i < n; i++) {
            b.put((byte) (x >> (i * 8)));
        }
        // 4. Let On+1 = enc8(n).
        b.put((byte) n);
        // 5. Return O = O1 || O2 || ... || On || On+1.
        return b.array();
    }

    public static byte[] left_encode(long x) {
        // Validity Conditions: 0 ≤ x < 2^2040
        assert x >= 0;
        assert x <= Math.pow(2, 2040);
        // 1. Let n be the smallest positive integer for which 2^8n > x.
        int n = 1;
        while (Math.pow(2, 8 * n) <= x) {
            n++;
        }
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x satisfying:
        //      x = ∑ 2^(8(n-i)) * xi, for i = 1 to n.
        ByteBuffer b = ByteBuffer.allocate(n + 1);
        // 3. Let O0 = enc8(n).
        b.put((byte) n);
        // 4. Let Oi = enc8(xi), for i = 1 to n.
        for (int i = 1; i <= n; i++) {
            b.put((byte) (x >> ((n-i) * 8)));
        }
        // 5. Return O = O0 || O1 || ... || On−1 || On.
        return b.array();
    }

    public static byte[] encode_string(byte[] S) {
        // Validity Conditions: 0 ≤ len(S) < 2^2040
        int len = S.length;
        assert len <  Math.pow(2, 2040);

        byte[] lenS = left_encode(len * 8L);
        return Main.concat(lenS, S);
    }

    /**
     * Switch from absorbing to extensible squeezing.
     */
    public void xof() {
        if (kmac) {
            // mandatory padding as per the NIST specification
            update(right_encode_0, right_encode_0.length);
        }
        // the (binary cSHAKE suffix is 00, while the (binary) SHAKE suffix is 1111
        this.b[this.pt] ^= (byte)(this.ext ? 0x04 : 0x1F);
        // big-endian interpretation (right-to-left):
        // 0x04 = 00000100 = suffix 00, right padded with 1, right padded with 0*
        // 0x1F = 00011111 = suffix 1111, right-padded with 1, right-padded with 0*
        this.b[this.rsiz - 1] ^= (byte)0x80;
        // little-endian interpretation (left-to-right):
        // 1000 0000 = suffix 1, left-padded with 0*
        sha3_keccakf(b);
        this.pt = 0;
    }

    /**
     * Converts byte string to little endian then moves it to an array of long[]
     * Performs Keccak rounds
     * Converts back to byte[] and big endian
     * @param A the state array as a byte[] string
     */
    private void sha3_keccakf(byte[] A) {

        A = swap_endianness(A);

        // convert 8 bit bytes to 64 bit words
        long[] st = new long[25];
        for (int i = 0; i < 25; i++) {
            for (int j = 0; j < 8; j++) {
                st[i] ^= ((long) A[(i * 8) + j] & 0xFFL) << (8 * (7 - j));
            }
        }

        // actual iterations
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {
            st = Rnd(st, r);
        }

        // convert 64 bit words back to 8 bit bytes
        byte[] newA = new byte[200];
        for (int i = 0; i < 25; i++) {
            for (int j = 0; j < 8; j++) {
                newA[(i * 8) + j] ^= (st[i] >> (8 * (7 - j))) & 0xFFL;
            }
        }

        this.b = swap_endianness(newA);
    }

    private long[] Rnd(long[] st, int ir) {
        long[] bc = new long[5];
        long t;

        // Theta
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j+= 5) {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[ir];

        return st;
    }

    /**
     * Swaps the endian-ness of 64 bit words
     * @param bytes
     * @return
     */
    private byte[] swap_endianness(byte[] bytes) {
        byte[] swap = new byte[bytes.length];
        for (int i = 0; i < bytes.length;) {
            for (int j = 7; j >= -8; j-= 2) {
                swap[i] = bytes[i + j];
                i++;
            }
        }
        return swap;
    }

    private long ROTL64(long x, int y) {
        long left = x << y;
        long right = x >>> (64 - y);
        return left | right;
    }
}
