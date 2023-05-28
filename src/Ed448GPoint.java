import java.math.BigInteger;
import java.util.Arrays;

public class Ed448GPoint {
    public BigInteger x;
    public BigInteger y;

    public static final BigInteger p = new BigInteger("2").pow(448).subtract(new BigInteger("2").pow(224)).subtract(BigInteger.ONE);
    public static final BigInteger d = new BigInteger("-39081");
    public static final BigInteger r = new BigInteger("4").multiply(new BigInteger("2").pow(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885")));

    /**
     * Constructor for the neutral point (0, 1).
     */
    public Ed448GPoint() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    /**
     * Constructor given an x and y value.
     * @param x value on the x-axis
     * @param y value on the y-axis
     */
    public Ed448GPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }


    /**
     * Constructor given x and the least significant bit of y
     * @param x value on the x-axis
     * @param lsb least significant bit of y
     */
    public Ed448GPoint(BigInteger x, boolean lsb) {
        this.x = x;

        // 1 - x^2
        BigInteger numerator = BigInteger.ONE.subtract(x.multiply(x));
        numerator = numerator.mod(p);

        // 1 + 39081x^2
        BigInteger denominator = x.multiply(x).multiply(new BigInteger("39081"));
        denominator = BigInteger.ONE.add(denominator);
        denominator = denominator.modInverse(p);

        BigInteger radicand = numerator.multiply(denominator);
        radicand = radicand.mod(p);

        this.y = sqrt(radicand, p, lsb);

    }

    /**
     * Generates a point from a byte representation of x and y
     * @param bytes a byte representation of x and y
     * @return an Ed448GPoint from the given bytes
     */
    public static Ed448GPoint pointFromBytes(byte[] bytes) {
        byte[] xBytes = Arrays.copyOfRange(bytes, 0, bytes.length - 1);
        byte yByte = bytes[bytes.length - 1];
        boolean lsb = yByte == 1;
        return new Ed448GPoint(new BigInteger(xBytes), lsb);
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

    /**
     * Checks if this point equals another point.
     * @param other an Ed448GPoint
     * @return True if they are equal, otherwise false.
     */
    public boolean equals(Ed448GPoint other) {
        return this.x.equals(other.x) && this.y.equals(other.y);
    }

    /**
     * Checks if this point is on the elliptic curve.
     * @return True if this point is on the curve, otherwise false.
     */
    public boolean isOnCurve() {
        // x^2 + y^2
        BigInteger lhs = this.x.pow(2).add(this.y.pow(2));
        lhs = lhs.mod(p);

        // 1 + d * x^2 * y^2
        BigInteger rhs = BigInteger.ONE.add(d.multiply(this.x.pow(2)).multiply(this.y.pow(2)));
        rhs = rhs.mod(p);
        return lhs.equals(rhs);
    }

    /**
     * Gives the negation of this point
     * @return the negation of this point
     */
    public Ed448GPoint opposite() {
        Ed448GPoint b = new Ed448GPoint(this.x, this.y);
        b.x = b.x.negate().mod(p);
        return b;
    }

    /**
     * Adds two points together.
     * @param b another point
     * @return the sum of the two points
     */
    public Ed448GPoint add(Ed448GPoint b) {
        BigInteger numerator = (this.x.multiply(b.y)).add(this.y.multiply(b.x));
        numerator = numerator.mod(p);

        BigInteger denominator = BigInteger.ONE.add(d.multiply(this.x).multiply(b.x).multiply(this.y).multiply(b.y));
        denominator = denominator.modInverse(p);

        BigInteger x = (numerator.multiply(denominator)).mod(p);


        numerator = (this.y.multiply(b.y)).subtract(this.x.multiply(b.x));
        numerator = numerator.mod(p);

        denominator = BigInteger.ONE.subtract(d.multiply(this.x).multiply(b.x).multiply(this.y).multiply(b.y));
        denominator = denominator.modInverse(p);

        BigInteger y = (numerator.multiply(denominator)).mod(p);

        return new Ed448GPoint(x, y);
    }

    /**
     * Multiplies this point with a given scalar s.
     * Implemented from the pseudocode for Double-and-add, Iterative algorithm, index increasing from this page:
     * https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
     * @param s a scalar
     * @return the product of this point and the given scalar s
     */
    public Ed448GPoint multiply(BigInteger s) {
        // s = (sk sk-1 ... s1 s0)2, sk = 1.
        Ed448GPoint V = new Ed448GPoint();
        Ed448GPoint temp = new Ed448GPoint(this.x, this.y); // initialize with sk*P, which is simply P
        String bits = s.toString(2);
        for (int i = bits.length() - 1; i >= 0; i--) { // scan over the k bits of s
            if ((bits.charAt(i) == '1')) { // test the i-th bit of s
                V = V.add(temp);               // invoke the Edwards point addition formula
            }
            temp = temp.add(temp);          // invoke the Edwards point addition formula
        }
        return V;   // now finally V = s*P
    }

//    public Ed448GPoint multiply(BigInteger s) {
//        String bits = s.toString(2);
//        Ed448GPoint res = new Ed448GPoint(this.x, this.y);
//        for (int i = 1; i < bits.length(); i++) {
//            res = res.add(res);
//            if (bits.charAt(i) == '1') {
//                res = res.add(this);
//            }
//        }
//        return res;
//    }



    /**
     * Converts this point to a byte array representation
     * @return a byte array representation of this point
     */
    public byte[] getBytes() {
        byte[] xBytes = this.x.toByteArray();
        byte[] zeroPad = new byte[57 - xBytes.length];
        Arrays.fill(zeroPad, (byte)0);
        byte[] yByte = new byte[1];
        yByte[0] = this.y.mod(BigInteger.TWO).equals(BigInteger.ZERO) ? (byte) 0 : (byte) 1;
        byte[] bytes = Main.concat(zeroPad, xBytes);
        bytes = Main.concat(bytes, yByte);

        return bytes;
    }

}
