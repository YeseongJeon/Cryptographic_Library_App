import java.math.BigDecimal;
import java.math.BigInteger;

public class Ed448GPoint {
    public BigInteger x;
    public BigInteger y;
    public BigInteger p;
    public BigInteger d = new BigInteger("-39801");

    public Ed448GPoint() {
        this.x = new BigInteger("0");
        this.y = new BigInteger("1");
        BigDecimal bd = new BigDecimal("7.26839E+134");
        this.p = bd.toBigInteger();
    }

    public Ed448GPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
        BigDecimal bd = new BigDecimal("7.26839E+134");
        this.p = bd.toBigInteger();
    }

    // Point from x and lsb of y
    // No clue if this is right, not sure where to find more info on this
    public Ed448GPoint(BigInteger x) {
        this.x = x;
        BigDecimal bd = new BigDecimal("7.26839E+134");
        this.p = bd.toBigInteger();

        BigInteger numerator = x.multiply(x);
        numerator = BigInteger.ONE.subtract(numerator);
        numerator = numerator.mod(p);

        BigInteger denominator = x.multiply(x).multiply(new BigInteger("39081"));
        denominator = BigInteger.ONE.add(denominator);
        denominator = denominator.modInverse(p);

        BigInteger radicand = numerator.multiply(denominator);
        radicand = radicand.mod(p);

        this.y = sqrt(radicand, p, true);

    }

    /**
     * Compute a square root of v mod p with a specified least significant bit,
     * if such a root exists.
     * @author Professor Paulo Barreto
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0)
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *         if such a root exists, otherwise null
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public boolean isEqual(Ed448GPoint a, Ed448GPoint b) {
        return a.x.equals(b.x) && a.y.equals(b.y);
    }

    public Ed448GPoint opposite(Ed448GPoint a) {
        Ed448GPoint b = new Ed448GPoint(a.x, a.y);
        b.x = b.x.negate();
        return b;
    }

    public Ed448GPoint add(Ed448GPoint b) {
        BigInteger numerator = (this.x.multiply(b.y)).add(this.y.multiply(b.x));
        numerator = numerator.mod(this.p);

        BigInteger denominator = BigInteger.ONE.add(this.d.multiply(this.x).multiply(b.x).multiply(this.y).multiply(b.y));
        denominator = denominator.modInverse(p);

        BigInteger x = (numerator.multiply(denominator)).mod(p);


        numerator = (this.y.multiply(b.y)).subtract(this.x.multiply(b.x));
        numerator = numerator.mod(this.p);

        denominator = BigInteger.ONE.subtract(this.d.multiply(this.x).multiply(b.x).multiply(this.y).multiply(b.y));
        denominator = denominator.modInverse(this.p);

        BigInteger y = (numerator.multiply(denominator)).mod(p);

        return new Ed448GPoint(x, y);
    }

    public Ed448GPoint product(Ed448GPoint P, long k) {
        // s = (sk sk-1 ... s1 s0)2, sk = 1.
        Ed448GPoint V = new Ed448GPoint(P.x, P.y); // initialize with sk*P, which is simply P

        for (long i = k - 1; i >= 0; i--) { // scan over the k bits of s
            V = V.add(P);       // invoke the Edwards point addition formula
            if ((k >> i & 0x01) == 0x01) { // test the i-th bit of s
                V = V.add(P);               // invoke the Edwards point addition formula
            }
        }
        return V;   // now finally V = s*P
    }

}
