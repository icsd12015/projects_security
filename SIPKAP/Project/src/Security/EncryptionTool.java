package Security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
/**
 * @author icsd12015 *
 */
//Περοιέχει μεθόδους για τη Συμμετρικη και Ασσυμετρη κρυπτογραφηση
public class EncryptionTool {

    //Μεθοδος για κρυπτογραφηση με παραμετρους
    //τα δεδομενα για κρυπτογραφηση, το κλειδι κρυπτογραφησης, τον αλγοριθμπ, αν το mode του αλγοριθμου κανει χρηση initiation vector και τον security provider
    public static byte[] Encrypt (byte[] plain, Key key, String algorithm, boolean useIV, Provider security_provider) throws
            NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {

        Cipher cipher = Cipher.getInstance(algorithm, security_provider);
        if (useIV) {
            IvParameterSpec iv = EncryptionTool.generateIV(cipher.getBlockSize());
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] m = cipher.doFinal(plain);
            return EncryptionTool.appendIV(m, iv.getIV());
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plain);
        }
    }

    //Μεθοδος για αποκρυπτογραφηση με παραμετρους
    //το κρυπτογραφημα, το κλειδι κρυπτογραφησης, τον αλγοριθμπ, αν το mode του αλγοριθμου κανει χρηση initiation vector και τον security provider
    public static byte[] Decrypt (byte[] encrypted, Key key, String algorithm, boolean useIV, Provider security_provider) throws
            NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, IOException {

        Cipher cipher = Cipher.getInstance(algorithm, security_provider);
        if (useIV) {
            IvParameterSpec iv = EncryptionTool.retrieveIV(encrypted, cipher.getBlockSize());
            byte[] cipherblock = EncryptionTool.retrieveCipherBlock(encrypted, cipher.getBlockSize());
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(cipherblock);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
            return cipher.doFinal(encrypted);
        }
    }

    //Μεθοδος για την δημιουργια initiation vector
    public static IvParameterSpec generateIV (final int ivSizeBytes) {
        final byte[] iv = new byte[ivSizeBytes];
        final SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    //Μεθοδος για την προσθηκη initiation vector στο κρυπτογραφημα
    public static byte[] appendIV (byte[] eData, byte[] iv) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(iv);
        os.write(eData);
        return os.toByteArray();
    }
    //Μεθοδος για την ανακτηση του initiation vector απο το κρυπτογραφημα
    public static IvParameterSpec retrieveIV (byte[] eData, int length) throws IOException {
        ByteArrayInputStream is = new ByteArrayInputStream(eData);
        byte[] ivbytes = new byte[length];
        is.read(ivbytes);
        return new IvParameterSpec(ivbytes);
    }
    //Μεθοδος για την ανακτηση των καθαρων αποκρυπτογραφημενων δεδομενων απο το κρυπτογραφημα που περιεχει και το initiation vector
    public static byte[] retrieveCipherBlock (byte[] eData, int offset) throws IOException {
        ByteArrayInputStream is = new ByteArrayInputStream(eData);
        is.read(new byte[offset]);
        byte[] cipherBlock = new byte[eData.length - offset];
        is.read(cipherBlock);
        return cipherBlock;
    }

}
