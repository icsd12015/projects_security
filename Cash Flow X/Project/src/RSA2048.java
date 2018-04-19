import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//Η κλαση για αποκρυπτογραφηση με τον αλγοριθμο RSA
public class RSA2048 {

    private final String KEY_FILEPATH = "Folders/AppKey";

    public static byte[] encrypt(byte[] plain, Key publicKey) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        byte[] cipherText;

         //Δημιουργια Cipher με τον αλγοριθμο RSA 
        Cipher cipher = Cipher.getInstance("RSA");
        //και το θετουμε για κρυπτογραφηση με το δημοσιο κλειδι
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //Κρυπτογραφηση κειμενου
        cipherText = cipher.doFinal(plain);

        return cipherText;
    }

    public static byte[] decrypt(byte[] encrypted, Key privateKey) throws InvalidKeyException,
            IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException,
            BadPaddingException {
        byte[] dectyptedText;

        //Δημιουργια Cipher με τον αλγοριθμο RSA 
        final Cipher cipher = Cipher.getInstance("RSA");

        //και το θετουμε για κρυπτογραφηση με το ιδιωτικο κλειδι
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        //Αποκρυπτογραφηση κειμενου
        dectyptedText = cipher.doFinal(encrypted);

        return dectyptedText;
    }

    //Αυτες οι μεθοδοι ειναι για κατασκευη των δημοσιων και ιδιωτικων κλειδιων του αλγοριμου RSA επειτα απο αποκωδικοποιση τους απο Base64
    public static PublicKey constructPublicKey(String skey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PublicKey publicKey = null;
        byte[] publicKeyBytes = Base64.getDecoder().decode(skey);
        publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(publicKeyBytes));
        return publicKey;
    }

    public static PrivateKey constructPrivateKey(String skey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PrivateKey privateKey = null;
        byte[] privateKeyBytes = Base64.getDecoder().decode(skey);
        privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyBytes));
        return privateKey;
    }
}
