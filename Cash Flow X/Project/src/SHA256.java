
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//Κλαση που υλοποιει την συναρτηση κατακερματησμου με τον αλγοριθμο SHA-256
public class SHA256 {

     public static byte[] Hash(byte[] plain) throws NoSuchAlgorithmException {
         //Dhmioyrgia tου MessageDigest με τον αλγοριθμο SΗΑ-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte byteData[] = md.digest(plain); //Κατακερματισμος
        return byteData;

    }
    //Παρομοια μεθοδος απλως αυτη τη φορα προσθετουμε και τα salt στη συνοψη
    public static byte[] HashWithSalt(byte[] plain, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte byteData[] = md.digest(plain);
        return byteData;

    }
    //Μεθοδος για τη δημιουργια τυχαιων salt αλφαρηθμιτικων με την java.security.SecureRandom
    public static byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte bytes[] = new byte[20];
        sr.nextBytes(bytes);
        return bytes;
    }
}
