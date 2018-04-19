package MultiKAP.KAProtocols;

import MultiKAP.Tools.EncryptionTool;
import MultiKAP.Tools.KeyTool;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
/**
 *
 * @author icsd12015 icsd11162
 */
public class EKAP {

    private final Provider security_provider;

    public EKAP () {

        this.security_provider = new BouncyCastleProvider();
        Security.setProperty("crypto.policy", "unlimited");

    }
    //Υλοποιηση ενος σεναριου συμφωνιας κλειδιου αναμεσα σε δυο οντοτητες (Alice και Bob) βαση του απλου πρωτόκολλου ενθυλακωσης συμμετρικου κλειδιου
    public void run (PrintStream out)  {
        try {
            int step = 0;

            step++;//Δημιουργειται το ζυγος δημοσιου και ιδιωτικου κλειδιου (KeyPair) της Alice που θα χρησιμοποιηθει για την ενθυλακωση

            out.println("\n\n" + Ansi.MAGENTA + step + ")" + Ansi.CYAN + "Alice generates her RSA KeyPair..." + Ansi.SANE);
            KeyPair aliceKeysRSA = KeyTool.generateKeyPair(2048, "RSA", security_provider); //RSA 2048 BouncyCastleProvider
            out.println(Ansi.GREEN + "\n\tAlice's KeyPair loaded:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceKeysRSA.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceKeysRSA.getPrivate().getFormat()
                    + Ansi.YELLOW + "\nPublic Key Size: " + Ansi.SANE + aliceKeysRSA.getPublic().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\nPrivate Key Size: " + Ansi.SANE + aliceKeysRSA.getPrivate().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeysRSA.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nAlice's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeysRSA.getPrivate().getEncoded()));

            step++;//"Αποστολη" δημοσιου κλειδιου

            out.println("\n\n" + Ansi.MAGENTA + step + ")" + Ansi.CYAN + " Alice encodes her RSA public key, and sends it to Bob..." + Ansi.SANE);
            byte[] aliceEncodedPubKey = aliceKeysRSA.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's PublicKey Bytes" + Ansi.SANE);

            step++; //Δημιουργια του συμμετρικου κλειδιου (SecretKey) απο Bob

            out.println("\n\n" + Ansi.MAGENTA + step + ")" + Ansi.CYAN + " Bob generates the Common SecretKey they are going to use..." + Ansi.SANE);
            SecretKey Kb = KeyTool.getRandomKey(256, "AES", security_provider); //AES 256 BouncyCastleProvider

            out.println(Ansi.GREEN + "\n\tCommon SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + Kb.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + Kb.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + Kb.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nCommon SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(Kb.getEncoded()));

            step++; //Ενθυλακωση του συμμετρικου κλειδιου που δημιουργεισε με RSA με το κλειδι που του "εστειλε" η Alice

            out.println(
                    "\n\n" + Ansi.MAGENTA + step + ")" + Ansi.CYAN + " Bob encodes the Common SecretKey he generated, encrypts it with Alice's public key, and sends the encncrypted bytes to Alice..." + Ansi.SANE);
            PublicKey bobRSAPubAlice = KeyTool.constructPublicKey(aliceEncodedPubKey, "RSA", security_provider);
            byte[] EK = EncryptionTool.Encrypt(Kb.getEncoded(), bobRSAPubAlice, "RSA", false, security_provider);
            out.println(Ansi.GREEN + "\n\tBob -> Alice: " + Ansi.SANE
                    + Ansi.YELLOW + "\n\nEncoded Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(EK));

            step++; //H Alice "παραλαμβανει" το ενθυλακωμενο συμμετρικο κλειδι που της εστειλε ο Bob και το απενθυλακωνει με το ιδιωτικο κλειδι της
            //και ξανα δημιουργει το SecretKey απο τα απενθυλακωμενα bytes

            out.println(
                    "\n\n" + Ansi.MAGENTA + step + ")" + Ansi.CYAN + "  Alice receives the Encrypted Common SecretKey bytes, decrypts and reconstructs it..." + Ansi.SANE);

            byte[] Dm = EncryptionTool.Decrypt(EK, aliceKeysRSA.getPrivate(), "RSA", false, security_provider);

            SecretKey Ka = (SecretKey) KeyTool.constructKey(Dm, "AES");

            out.println(Ansi.GREEN + "\n\tCommon SecretKey decrypted and reconstucted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + Ka.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + Ka.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + Ka.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nCommon SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(Ka.getEncoded()));

            step++; //H Alice κρυπτογραφει συμμετρικα ενα μηνυμα με το SecretKey της χρησιμοποιωντας AES με CBC 

            out.println(
                    "\n\n" + DHKAP.Ansi.MAGENTA + step + ")" + DHKAP.Ansi.CYAN + " Alice encrypts with the Common Secret Key, using AES in CBC mode with PKCS#5 Padding, a message then encodes it and sends it to Bob..." + DHKAP.Ansi.SANE);

            Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", security_provider);
            IvParameterSpec ivForCBC = EncryptionTool.generateIV(aliceCipher.getBlockSize()); //Δημιουργεια IV
            aliceCipher.init(Cipher.ENCRYPT_MODE, Ka, ivForCBC);
            byte[] cipherblock = aliceCipher.doFinal("This is ma big secret".getBytes());
            byte[] cipherblockwithIV = EncryptionTool.appendIV(cipherblock, ivForCBC.getIV()); //Δημιουργια τελικου block με το κρυπτογραφημα και διπλα το IV
            out.println(DHKAP.Ansi.GREEN + "\nAlice -> Bob: [encrypted message encoded]" + DHKAP.Ansi.SANE);

            step++; //O Bob "παραλαμβανει" και αποκρυπτογραφει με SecretKey του το κρυπτογραφημα χρησιμοποιωντας AES με CBC

            out.println(
                    "\n\n" + DHKAP.Ansi.MAGENTA + step + ")" + DHKAP.Ansi.CYAN + " Bob decrypts with the Common Secret Key, using the same algorithm, mode and padding, the encrypted message Alice sent him..." + DHKAP.Ansi.SANE);

            Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", security_provider);
            IvParameterSpec iv = EncryptionTool.retrieveIV(cipherblockwithIV, aliceCipher.getBlockSize()); //Παιρνει το IV απο το block
            byte[] cipherblockre = EncryptionTool.retrieveCipherBlock(cipherblockwithIV, aliceCipher.getBlockSize());//Παιρνει το κρυπτογραφημα απο το block
            bobCipher.init(Cipher.DECRYPT_MODE, Kb, iv);
            byte[] recovered = bobCipher.doFinal(cipherblockre);
            out.println(DHKAP.Ansi.YELLOW + "\nDecrypted message: " + DHKAP.Ansi.SANE + new String(recovered));

        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchProviderException |
                 IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException | IOException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        } 
    }


    // <editor-fold defaultstate="collapsed" desc="Colors Variables">     + +
    public final class Ansi {

        // Color code strings from:
        // http://www.topmudsites.com/forums/mud-coding/413-java-ansi.html
        public static final String SANE = "\u001B[0m";

        public static final String HIGH_INTENSITY = "\u001B[1m";
        public static final String LOW_INTENSITY = "\u001B[2m";

        public static final String ITALIC = "\u001B[3m";
        public static final String UNDERLINE = "\u001B[4m";
        public static final String BLINK = "\u001B[5m";
        public static final String RAPID_BLINK = "\u001B[6m";
        public static final String REVERSE_VIDEO = "\u001B[7m";
        public static final String INVISIBLE_TEXT = "\u001B[8m";

        public static final String BLACK = "\u001B[30m";
        public static final String RED = "\u001B[31m";
        public static final String GREEN = "\u001B[32m";
        public static final String YELLOW = "\u001B[33m";
        public static final String BLUE = "\u001B[34m";
        public static final String MAGENTA = "\u001B[35m";
        public static final String CYAN = "\u001B[36m";
        public static final String WHITE = "\u001B[37m";

        public static final String BACKGROUND_BLACK = "\u001B[40m";
        public static final String BACKGROUND_RED = "\u001B[41m";
        public static final String BACKGROUND_GREEN = "\u001B[42m";
        public static final String BACKGROUND_YELLOW = "\u001B[43m";
        public static final String BACKGROUND_BLUE = "\u001B[44m";
        public static final String BACKGROUND_MAGENTA = "\u001B[45m";
        public static final String BACKGROUND_CYAN = "\u001B[46m";
        public static final String BACKGROUND_WHITE = "\u001B[47m";

    }// </editor-fold>
}
