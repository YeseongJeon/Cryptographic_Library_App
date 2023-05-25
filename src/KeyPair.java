public class KeyPair {
    public byte[] privateKey;
    public Ed448GPoint publicKey;

    KeyPair(byte[] privateKey, Ed448GPoint publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}
