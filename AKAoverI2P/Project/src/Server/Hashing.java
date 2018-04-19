package Server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//Κλαση που κανει κατακερματισμο String με τον αλγοριθμο που δινεται ως ορισμα
public class Hashing {

     public static byte[] Hash(byte[] plain,String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte byteData[] = md.digest(plain); 
        return byteData;
    }

    public static byte[] HashWithSalt(byte[] plain, byte[] salt,String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(salt);
        byte byteData[] = md.digest(plain);
        return byteData;
    }
    //Μεθοδος για τη δημιουργια τυχαιων αλφαρηθμιτικων με την java.security.SecureRandom
    public static byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte bytes[] = new byte[20];
        sr.nextBytes(bytes);
        return bytes;
    }
    

}
