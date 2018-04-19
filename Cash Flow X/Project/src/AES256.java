
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

//Η κλαση για κρυπτογραφηση με τον αλγοριθμο AES-256 
public class AES256 {

    //H encrypt κρυπτογραφει ενα κειμενο με το συμμετρικο κλειδι που δινουμε

    public static String Encrypt(String plain, Key key) throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {

        //Δημιουργια Cipher με τον αλγοριθμο AES 
        Cipher cipher = Cipher.getInstance("AES");
        //και το θετουμε για κρυπτογραφηση με το συμμετρικο κλειδι
        cipher.init(Cipher.ENCRYPT_MODE, key);
        //Κρυπτογραφηση κειμενου
        byte[] cipherBytes = cipher.doFinal(plain.getBytes());
        //Μετατροπη του σε κωδικοποιηση Base64 για αποθηκευση του στο αρχειο
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    //H decrypt αποκρυπτογραφει ενα κειμενο με το συμμετρικο κλειδι που δινουμε

    public static String Decrypt(String encrypted, Key key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        byte[] byteData;
        //Δημιουργια Cipher με τον αλγοριθμο AES 
        Cipher cipher = Cipher.getInstance("AES");
        //και το θετουμε για αποκρυπτογραφηση με το συμμετρικο κλειδι
        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        //Αποκρυπτογραφηση δεδομενων (αφου πρωτα μετατραπουν απο Base64)
        byteData = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(byteData);
    }

    //Μεθοδος για την δημιουργια συμμετρικων κλειδιων
    public static Key getRandomKey() throws NoSuchAlgorithmException {
        Key key;
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); //Αλγοριθμος AES
        keyGen.init(256); //Μεγεθος κλειδιου 256 
        key = keyGen.generateKey(); //Δημιουργια
        return key;
    }

    //Κατασκευη κλειδιου απο πινακα bytes
    public static Key getKeyFromBytes(byte[] data) {
        return new SecretKeySpec(data, "AES");
    }
}
