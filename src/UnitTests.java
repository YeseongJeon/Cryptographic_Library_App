import org.junit.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class UnitTests {

    public static final Ed448GPoint G = new Ed448GPoint(new BigInteger("8"), true);
    public static final BigInteger FOUR = new BigInteger("4");

    // 0 * G == O
    @Test
    public void testMutliplyByZero() {
        Assert.assertTrue(G.multiply(BigInteger.ZERO).equals(new Ed448GPoint()));
    }

    // 1 * G == G
    @Test
    public void testMultiplyByOne() {
        Assert.assertTrue(G.multiply(BigInteger.ONE).equals(G));
    }

    // G + (-G) == O
    @Test
    public void testSumWithOpposite() {
        Assert.assertTrue(G.add(G.opposite()).equals(new Ed448GPoint()));
    }

    // 2 * G == G + G
    @Test
    public void testMultiplyByTwo() {
        Assert.assertTrue(G.multiply(BigInteger.TWO).equals(G.add(G)));
    }

    // 4 * G == 2 * (2 * G)
    @Test
    public void testMultiplyByFour() {
        Assert.assertTrue(G.multiply(FOUR).equals(G.multiply(BigInteger.TWO).multiply(BigInteger.TWO)));
    }

    // 4 * G != O
    @Test
    public void testProductIsNotO() {
        Assert.assertFalse(G.multiply(FOUR).equals(new Ed448GPoint()));
    }

    // r * G == O
    @Test
    public void testMultiplyByR() {
        Ed448GPoint lhs = G.multiply(Ed448GPoint.r);
        Assert.assertTrue(lhs.equals(new Ed448GPoint()));
    }

    // k * G == (k mod r) * G
    @Test
    public void testProducts1() {
        int randomTests = 100;
        int passed = 0;
        for (int i = 0; i < randomTests; i++) {
            BigInteger k = new BigInteger(448, new Random());
            Ed448GPoint lhs = G.multiply(k);
            Ed448GPoint rhs = G.multiply(k.mod(Ed448GPoint.r));
            if (rhs.equals(lhs)) { passed++; }
        }
        Assert.assertEquals(randomTests, passed);
    }

    // (k + 1) * G == (k * G) + G
    @Test
    public void testProducts2() {
        int randomTests = 100;
        int passed = 0;
        for (int i = 0; i < randomTests; i++) {
            BigInteger k = new BigInteger(448, new Random());
            Ed448GPoint lhs = G.multiply(k.add(BigInteger.ONE));
            Ed448GPoint rhs = G.multiply(k).add(G);
            if (rhs.equals(lhs)) { passed++; }
        }
        Assert.assertEquals(randomTests, passed);
    }

    // (k + t) * G = (k * G) + (t * G)
    @Test
    public void testProducts3() {
        int randomTests = 100;
        int passed = 0;
        for (int i = 0; i < randomTests; i++) {
            BigInteger k = new BigInteger(448, new Random());
            BigInteger t = new BigInteger(448, new Random());
            Ed448GPoint lhs = G.multiply(k.add(t));
            Ed448GPoint rhs = G.multiply(k).add(G.multiply(t));
            if (rhs.equals(lhs)) { passed++; }
        }
        Assert.assertEquals(randomTests, passed);
    }

    // (k * (t * G) == t * (k * G) == (k * t mod r) * G
    @Test
    public void testProducts4() {
        int randomTests = 100;
        int passed = 0;
        for (int i = 0; i < randomTests; i++) {
            BigInteger k = new BigInteger(448, new Random());
            BigInteger t = new BigInteger(448, new Random());
            Ed448GPoint lhs = G.multiply(t).multiply(k);
            Ed448GPoint middle = G.multiply(k).multiply(t);
            Ed448GPoint rhs = G.multiply(k.multiply(t).mod(Ed448GPoint.r));
            if (lhs.equals(middle) && middle.equals(rhs)) {
                passed++;
            }
        }
        Assert.assertEquals(randomTests, passed);
    }
}
