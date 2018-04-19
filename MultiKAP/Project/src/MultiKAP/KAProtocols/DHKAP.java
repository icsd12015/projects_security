package MultiKAP.KAProtocols;

import MultiKAP.Tools.EncryptionTool;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public class DHKAP {

    private final Provider security_provider;

    private BigInteger P;
    private BigInteger G;
    private int L;

    public DHKAP () {

        this.security_provider = new BouncyCastleProvider();
        Security.setProperty("crypto.policy", "unlimited");

    }

    //Υλοποιηση ενος σεναριου συμφωνιας κλειδιου αναμεσα σε δυο οντοτητες (Alice και Bob) βαση του πρωτόκολλου Diffie Hellman
    public void run (PrintStream out) {
        try {

            out.println(Ansi.RED + "\t\tDIFFIE - HELLMAN ALGORITHM SESSION EXAMPLE:\n\n" + Ansi.SANE);

            int step = 0;

            step++; //Δημιουργια των δυο πρωτων που αποτελουν τις παραμετρους του Diffie Hellman

            out.println(Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates the Common DiffieHellman Parameters..."
                    + Ansi.SANE);
//            this.generateDHparameters(2048);
//            this.generateDHparametersFast(2048);
            this.setDHparamsRFC();
            out.println(Ansi.GREEN + "\n\tDiffieHellman parameters generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nP (modulus): " + Ansi.SANE + P
                    + Ansi.YELLOW + "\nG (generator): " + Ansi.SANE + G
                    + Ansi.YELLOW + "\nL (exponent size): " + Ansi.SANE + L + " bits");

            step++; //Δηνιουργια του ζευγους κλειδιων Diffie Hellman για την Alice
            //οπου δημοσιο ειναι το g^x και το ιδιωτικο το x

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates her DiffieHellman KeyPair using those parameters..."
                    + Ansi.SANE);
            DHParameterSpec dhParams = new DHParameterSpec(P, G, L);
            KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DiffieHellman", security_provider);
            aliceKeyPairGen.initialize(dhParams);

            KeyPair aliceKeys = aliceKeyPairGen.generateKeyPair();
            out.println(Ansi.GREEN + "\n\tAlice's KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\nPublic Key Size: " + Ansi.SANE + aliceKeys.getPublic().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\nPrivate Key Size: " + Ansi.SANE + aliceKeys.getPrivate().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nAlice's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeys.getPrivate().getEncoded()));

            step++;//Αρχικοποιηση του KeyAgreement με το ιδιωτικο κλειδι της που δημιουργησε (οι παραμετροι του  Diffie Hellman υπαρχουν σε αυτο)

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice initializes her DiffieHellman KeyAgreement instance with her private key..."
                    + Ansi.SANE);

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DiffieHellman", security_provider);
            aliceKeyAgree.init(aliceKeys.getPrivate());
            out.println(Ansi.GREEN + "\n\tAlice's " + aliceKeyAgree.getAlgorithm() + " KeyAgreement initialized" + Ansi.SANE);

            step++; //"Αποστολη" των bytes του DHPublicKey της Alice στον Bob

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encodes her DHPublicKey (including the common DH parameters), and sends it to Bob..."
                    + Ansi.SANE);

            byte[] aliceEncodedPubKey = aliceKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's PublicKey Bytes" + Ansi.SANE);

            step++; //"Παραλαβη" των bytes του συμμετρικου κλειδιου της Alice απο τον Bob και ανακατασκευη σε DHPublicKey

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob receives Alice's encoded DHPublicKey and reconstructs it..."
                    + Ansi.SANE);

            KeyFactory bobKeyFac = KeyFactory.getInstance("DH", security_provider);
            X509EncodedKeySpec alicePubKeySpec = new X509EncodedKeySpec(aliceEncodedPubKey);
            DHPublicKey alicePubKey = (DHPublicKey) bobKeyFac.generatePublic(alicePubKeySpec);
            out.println(Ansi.GREEN + "\nAlice's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(alicePubKey.getEncoded()));

            step++; //Ο Bob εξαγει τις παραμετρους του Diffie Hellman απο το κλειδι της Alice

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob gets the Common DiffieHellman Parameters Alice generated from her DHPublicKey.."
                    + Ansi.SANE);

            DHParameterSpec alicePubKeyDHParams = alicePubKey.getParams();
            out.println(Ansi.GREEN + "\n\tDiffieHellman parameters from key:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nP: " + Ansi.SANE + alicePubKeyDHParams.getP()
                    + Ansi.YELLOW + "\n\nG: " + Ansi.SANE + alicePubKeyDHParams.getG()
                    + Ansi.YELLOW + "\n\nL: " + Ansi.SANE + alicePubKeyDHParams.getL());

            step++; //Δηνιουργια του ζευγους κλειδιων Diffie Hellman για τον Bob
            //οπου δημοσιο ειναι το g^y και το ιδιωτικο το y

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates his DiffieHellman KeyPair using those parameters..."
                    + Ansi.SANE);

            KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DiffieHellman", security_provider);
            bobKeyPairGen.initialize(alicePubKeyDHParams);
            KeyPair bobKeys = bobKeyPairGen.generateKeyPair();
            out.println(Ansi.GREEN + "\n\tBob's KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\n\nBob's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nBob's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPrivate().getEncoded()));

            step++; //Αρχικοποιηση του KeyAgreement με το ιδιωτικο κλειδι του που δημιουργησε (οι παραμετροι του  Diffie Hellman υπαρχουν σε αυτο)

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob initializes his DiffieHellman KeyAgreement with his private key..."
                    + Ansi.SANE);

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DiffieHellman", security_provider);
            bobKeyAgree.init(bobKeys.getPrivate());
            out.println(Ansi.GREEN + "\n\tBob's " + bobKeyAgree.getAlgorithm() + " KeyAgreement initialized" + Ansi.SANE);

            step++; //Δημιουργια του SecretKey που θα χρησιμοποιησουν απο τη KeyAgreement το οποιο αρχικοποειται με το δημοσιο κλειδι της Alice
            //K = g^y^x mod p

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates the Common Secret Key using Alice's public key and his private key..."
                    + Ansi.SANE);

            bobKeyAgree.doPhase(alicePubKey, true); //true γιατι ειναι (πρωτη και) τελευταια φαση του πρωτοκολλου
            byte[] bobEncodedSecretKey = bobKeyAgree.generateSecret();
            SecretKey bobSecretKey = new SecretKeySpec(bobEncodedSecretKey, 0, 32, "AES"); //32 bytes -> 256 bits

            out.println(Ansi.GREEN + "\n\tBob's Common SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobSecretKey.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobSecretKey.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + bobSecretKey.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nBob's Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSecretKey.getEncoded()));

            step++; //"Αποστολη"των bytes του DHPublicKey της Bob στην Alice

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob encodes his DH public key, and sends it to Alice..."
                    + Ansi.SANE);
            byte[] bobEncodedPubKey = bobKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tBob -> Alice: Bob's PublicKey Bytes" + Ansi.SANE);

            step++; //"Παραλαβη" των bytes του συμμετρικου κλειδιου του Bob απο την Alice και ανακατασκευη σε DHPublicKey

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice receives Bob's encoded DH public key and reconstructs it..."
                    + Ansi.SANE);

            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", security_provider);
            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(bobEncodedPubKey);
            DHPublicKey bobPubKey = (DHPublicKey) aliceKeyFac.generatePublic(bobPubKeySpec);
            out.println(Ansi.GREEN + "\n\tBob's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's Public Key:"
                    + Ansi.SANE + "\n" + Base64.toBase64String(bobPubKey.getEncoded()));

            step++; //Δημιουργια του SecretKey που θα χρησιμοποιησουν απο τη KeyAgreement το οποιο αρχικοποειται με το δημοσιο κλειδι του Bob
            //K = g^x^y mod p

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates the Common Secret Key usgin Bob's public key and her private key..."
                    + Ansi.SANE);

            aliceKeyAgree.doPhase(bobPubKey, true);//true γιατι ειναι (πρωτη και) τελευταια φαση του πρωτοκολλου
            byte[] aliceEncodedSecretKey = aliceKeyAgree.generateSecret();
            SecretKey aliceSecretKey = new SecretKeySpec(aliceEncodedSecretKey, 0, 32, "AES"); //32 bytes -> 256 bits

            out.println(Ansi.GREEN + "\n\tAlice's Common SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceSecretKey.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceSecretKey.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + aliceSecretKey.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nAlice's Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceSecretKey.getEncoded()));

            step++; //H Alice κρυπτογραφει συμμετρικα ενα μηνυμα με το SecretKey της χρησιμοποιωντας AES με CBC 

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encrypts with the Common Secret Key, using AES in CBC mode with PKCS#5 Padding, a message then encodes it and sends it to Bob..."
                    + Ansi.SANE);

            Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", security_provider);
            IvParameterSpec ivForCBC = EncryptionTool.generateIV(aliceCipher.getBlockSize());
            aliceCipher.init(Cipher.ENCRYPT_MODE, aliceSecretKey, ivForCBC);
            byte[] cipherblock = aliceCipher.doFinal("This is ma big secret".getBytes());
            byte[] cipherblockwithIV = EncryptionTool.appendIV(cipherblock, ivForCBC.getIV());
            out.println(Ansi.GREEN + "\nAlice -> Bob: [encrypted message encoded]" + Ansi.SANE);

            step++; //O Bob "παραλαμβανει" και αποκρυπτογραφει με SecretKey του το κρυπτογραφημα χρησιμοποιωντας AES με CBC

            out.println(
                    "\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob decrypts with the Common Secret Key, using the same algorithm, mode and padding, the encrypted message Alice sent him..."
                    + Ansi.SANE);

            Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", security_provider);
            IvParameterSpec iv = EncryptionTool.retrieveIV(cipherblockwithIV, aliceCipher.getBlockSize());
            byte[] cipherblockre = EncryptionTool.retrieveCipherBlock(cipherblockwithIV, aliceCipher.getBlockSize());
            bobCipher.init(Cipher.DECRYPT_MODE, bobSecretKey, iv);
            byte[] recovered = bobCipher.doFinal(cipherblockre);
            out.println(Ansi.YELLOW + "\nDecrypted message: "
                    + Ansi.SANE + new String(recovered) + "\n");

        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException | IOException ex) {
            ex.printStackTrace();
        }
    }

    //Δημιουργια παραμετρων για το DH με χρηση του AlgorithmParameterGenerator (αργο)
    public void generateDHparameters (int size) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(size);

        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

        P = dhSpec.getP();
        G = dhSpec.getG();
        L = dhSpec.getL();
    }

    //Δημιουργια παραμετρων για το DH με χρηση της BigInteger.probablePrime
    public void generateDHparametersFast (int size) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        P = BigInteger.probablePrime(size, new SecureRandom());
        G = BigInteger.probablePrime(size, new SecureRandom());
        L = size - 1;
    }

    //Παραμετροι για το DH απο το rfc3526
    public void setDHparamsRFC () {
        //https://tools.ietf.org/html/rfc3526
        P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        G = BigInteger.valueOf(2);
        L = 2047;
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
