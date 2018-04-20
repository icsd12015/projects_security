package Security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//Κλαση που κανει κατακερματισμο String με τον αλγοριθμο που δινεται ως ορισμα
public class Digest {

    public static byte[] HashWithSalt (byte[] plain, byte[] salt1, byte[] salt2, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(salt1);
        md.update(salt2);
        byte byteData[] = md.digest(plain);
        return byteData;
    }

    //Μεθοδος για τη δημιουργια τυχαιων αλφαρηθμιτικων με την java.security.SecureRandom

    public static byte[] generateSalt (int length) {
        SecureRandom sr = new SecureRandom();
        byte bytes[] = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

}
