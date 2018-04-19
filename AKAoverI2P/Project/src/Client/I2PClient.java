package Client;

//icsd12015 icsd11162 icsd11122
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import net.i2p.I2PException;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.data.DataFormatException;
import net.i2p.data.Destination;
import sun.misc.BASE64Decoder;

public class I2PClient {

    private final static String sPublicKeyEncoded
            = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnkIJsUgTDDoGvP04Rfzs\n"
            + "4CuxxuDo6CsC6lb9YwZk8V8Y2hWw1jw45hynCWECc/27qR664kmDTrNf4NqyvEah\n"
            + "Na4eKugHtyoaoR0Yt6s4zmNQ0yBIdIvvGU4rBxCHMTcHjiiihwWy0Mr3awVIzFrS\n"
            + "srlFtfa1roo57bx22JtL40z+3Hn1Q1bEtokkqD8cDRGnYfo5OGZFdCeE26651Sh1\n"
            + "cCLDMF9fEaP0iPqles59hK8ySgWGaeK+pWeZofwqa5I2ZZBA/DayeD1472lCVxb7\n"
            + "6OtkF3iTj+acIScS/sJwPpPxUDxR03qHrDal+fZMVX5OLlxDZMjd8rxHAY73FOH6\n"
            + "awIDAQAB";

    private final static ArrayList<String> SymmetricAlgorithmsSupported = new ArrayList() {
        {
            add("Twofish");
            add("AES");
        }
    };

    private final static ArrayList<String> HashAlgorithsSupported = new ArrayList() {
        {
            add("Whirlpool");
            add("SHA-256");
        }
    };

    public static void main(String[] args) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        System.out.println(Ansi.BLUE + Ansi.HIGH_INTENSITY + "Client: " + Ansi.LOW_INTENSITY
                + "\n" + Ansi.GREEN + "        Connecting to I2P..");
        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        System.out.print(""
                + "\n" + Ansi.MAGENTA + "        Please enter a Destination: " + Ansi.BLACK);
        Scanner scanner = new Scanner(System.in);
        String destinationString;

        destinationString = scanner.next();

        Destination destination;
        try {
            destination = new Destination(destinationString);
        } catch (DataFormatException ex) {
            System.out.println("Destination string incorrectly formatted.");
            return;
        }
        I2PSocket socket;
        try {
            socket = manager.connect(destination);
        } catch (I2PException ex) {
            System.out.println("General I2P exception occurred!");
            return;
        } catch (ConnectException ex) {
            System.out.println("Failed to connect!");
            return;
        } catch (NoRouteToHostException ex) {
            System.out.println("Couldn't find host!");
            return;
        } catch (InterruptedIOException ex) {
            System.out.println("Sending/receiving was interrupted!");
            return;
        }
        try {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            //STEP 1
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 1**" + Ansi.LOW_INTENSITY);
            //Αποστολη μηνυματος χαιρετισμου 
            out.flush();
            out.writeObject(new String("Hello Bob!"));
            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Client:" + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "        Sent hello message.");

            //STEP 2
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 2**" + Ansi.LOW_INTENSITY);
            //Ληψη του τυχαιου αλφαριθμιτικου
            String sCookie = (String) in.readObject();
            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Server: " + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "           Server cookie: " + Ansi.BLACK + sCookie);

            //STEP 3
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 3**" + Ansi.LOW_INTENSITY);
            //Δημιουργια τυχαιου αλφαριθμιτικου 64 bit
            final byte[] randombytes = new byte[64];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(randombytes);
            String myCookie = Base64.getEncoder().encodeToString(randombytes);

            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Client: " + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "           Client cookie: " + Ansi.BLACK + myCookie);

            //Αποστολη του αλφαριθμιτικου που ληφθηκε και αυτου που δημιουργηθηκε και των σουιτων που υποστηριζονται 
            out.flush();
            out.writeObject(sCookie);
            out.flush();
            out.writeObject(myCookie);
            out.flush();
            out.writeObject(SymmetricAlgorithmsSupported);
            out.flush();
            out.writeObject(HashAlgorithsSupported);

            //Step 4
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 4**" + Ansi.LOW_INTENSITY);
            //Ληψη των επιλεγμενων σουιτων και του πιστοποιητικου
            String sSymmetricAlgoSelected = (String) in.readObject();
            String sHashAlgoSelected = (String) in.readObject();
            X509Certificate sCertificate = (X509Certificate) in.readObject();

            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Server: " + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "           Symetric encryption algorithm selected: " + Ansi.BLACK + sSymmetricAlgoSelected
                    + "\n" + Ansi.CYAN + "           Hash algorithm selected: " + Ansi.BLACK + sHashAlgoSelected);

            //Κατασκευη δημοσιου κλειδιου
            byte[] sPublicKeyBytes = (new BASE64Decoder()).decodeBuffer(sPublicKeyEncoded);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(sPublicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey sPublicKey = kf.generatePublic(spec);

            //Επιβεβαιωση πιστοποιητικου με το δημοσιο κλειδι
            sCertificate.verify(sPublicKey);
            System.out.println(""
                    + "\n" + Ansi.CYAN + "           Certificate authenticated succesfully.");

            //Step 5
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 5**" + Ansi.LOW_INTENSITY);
            //Δημιουργια τυχαιου αλφαριθμητικου 128 bits
            final byte[] RNbytes = new byte[128];
            sr = new SecureRandom();
            sr.nextBytes(RNbytes);
            String RN = Base64.getEncoder().encodeToString(RNbytes);
            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Client: " + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "           RN: " + Ansi.BLACK + RN);

            //Δημιουργια της συνοψης SHA256(myCookie + cCookie + RNdecrypted)
            byte[] digest = Hashing.Hash((sCookie + myCookie + RN).getBytes(), "SHA-256");
            System.out.println(""
                    + "\n" + Ansi.CYAN + "           SHA256 Digest: " + Ansi.BLACK + Base64.getEncoder().encodeToString(digest));
            //Χωρισμος της συνοψης σε δυο μερη
            byte[] oneHalf = Arrays.copyOfRange(digest, 0, 16);
            byte[] otherHalf = Arrays.copyOfRange(digest, 16, 32);

            System.out.println(""
                    + "\n" + Ansi.CYAN + "           First half of digest: " + Ansi.BLACK + Base64.getEncoder().encodeToString(oneHalf)
                    + "\n" + Ansi.CYAN + "           Second half of digest: " + Ansi.BLACK + Base64.getEncoder().encodeToString(otherHalf));
            //Δημιουργια κλειδιου με μεγεθος 128 bits απο το πρωτο μερος βαση του αλγοριθμου συμμετρικης κρυπτογραφησης που επιλεχτηκε 
            //Το αλλο μισο χρεισιμοποιειται αυτουσιο ως κλειδι για δημιουργια συνοψεων HMAC
            byte[] IntegrityKey = otherHalf;
            Key ConfidentialityKey = new SecretKeySpec(oneHalf, 0, oneHalf.length, sSymmetricAlgoSelected);

            System.out.println(""
                    + "\n" + Ansi.CYAN + "           ConfidentialityKey size: " + Ansi.BLACK + ConfidentialityKey.getEncoded().length * 8 + " bits."
                    + "\n" + Ansi.CYAN + "           IntegrityKey size: " + Ansi.BLACK + IntegrityKey.length * 8 + " bits."
                    + "\n" + Ansi.CYAN + "           Key for Confidentiality: " + Ansi.BLACK + Base64.getEncoder().encodeToString(ConfidentialityKey.getEncoded())
                    + "\n" + Ansi.CYAN + "           Key for Integrity: " + Ansi.BLACK + Base64.getEncoder().encodeToString(IntegrityKey));

            //Δημιουργια της συνοψης HMAC των σουιτων με τον αλγοριθμο κατακερματισμου μπου εχει επιλεχτει 
            String HmacDigest = HMAC.Hash(sSymmetricAlgoSelected + sHashAlgoSelected, IntegrityKey, sHashAlgoSelected);
            System.out.println(""
                    + "\n" + Ansi.CYAN + "           HMAC" + sHashAlgoSelected + " Digest: " + Ansi.BLACK + Base64.getEncoder().encodeToString(digest));
            
            //Κρυπτογραφηση του τυχαιου αλφαριθμιτικου με το δημοσιο κλειδι
            String RNencrypted = Encryption.Encrypt(RN, sPublicKey, "RSA");
            System.out.println(""
                    + "\n" + Ansi.CYAN + "           RN encrypted: " + Ansi.BLACK + RNencrypted);

            //Αποστολη του κρυπτογραφημενου αλφαριθμιτικου και της συνοψης HMAC
            out.flush();
            out.writeObject(RNencrypted);
            out.flush();
            out.writeObject(HmacDigest);

            //STEP 6
            System.out.println("\n" + Ansi.YELLOW + Ansi.HIGH_INTENSITY + "**STEP 6**" + Ansi.LOW_INTENSITY);
            //Ληψη του συμμετρικα κρυπτογραφημενου μηνυματος 
            String sEncryptedMSG = (String) in.readObject();
            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Server:" + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "        Verification message received encrypted: " + Ansi.BLACK + sEncryptedMSG);
            //Αποκρυπτογραφηση του συμμετρικα κρυπτογραφημενου μηνυματος 
            String sDecryptedMSG = Encryption.Decrypt(sEncryptedMSG, ConfidentialityKey, sSymmetricAlgoSelected);

            System.out.println("\n" + Ansi.BLUE + Ansi.HIGH_INTENSITY + "Client:" + Ansi.LOW_INTENSITY
                    + "\n" + Ansi.CYAN + "        Verification message decrypted: " + Ansi.BLACK + sDecryptedMSG);

//            socket.close();
        } catch (IOException ex) {
            System.out.println("Error occurred while sending/receiving!");
            ex.printStackTrace();
        } catch (ClassNotFoundException ex) {
            System.out.println("Class <Msg> is missing!");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            System.out.println("Certificate authentication failed!");
            try {
                socket.close();
            } catch (IOException ex1) {
                Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex1);
            }
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
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
