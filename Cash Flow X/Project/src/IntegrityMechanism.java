
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

//Αυτη η κλαση αφορα τον Μηχανισμο Ακεραιοτητας και περιεχει της μεθοδους που υλοποιηθηκαν για αυτον το σκοπο
public class IntegrityMechanism {

    //Μεθοδος για την ψηφιακη υπογραφη των δυο αρχειων καθε χρηστη
    public static int signUserFiles(String username, String signatureFileName) {
        FileInputStream fis = null;
        String user_dir = Main.USER_FILES_DIR_PATH + "/" + username;
        File user_income_file = new File(user_dir + "/" + "income.data");
        File user_outcome_file = new File(user_dir + "/" + "outcome.data");
        try {
            //Διαβασμα περιεχωμενων δυο αρχειων και δημιουργια των συνοψεων αυτων
            //Επειτα περνιουνται σε κωδικοποιηση Base64 στα strings filename_digestI kai filename_digestO
            fis = new FileInputStream(user_income_file);
            byte[] data = new byte[(int) user_income_file.length()];
            fis.read(data);
            fis.close();
            byte[] digest = SHA256.Hash(data);
            String filename_digestI = "income.data" + Main.separator + Base64.getEncoder().encodeToString(data);

            fis = new FileInputStream(user_outcome_file);
            data = new byte[(int) user_outcome_file.length()];
            fis.read(data);
            fis.close();
            digest = SHA256.Hash(data);
            String filename_digestO = "outcome.data" + Main.separator + Base64.getEncoder().encodeToString(data);

            //Τελος τα δυο αυτα string τα υπογραφει ψηφιακα η εφαρμογη με χρηση του ιδιωτικου της κλειδιου
            byte[] sig = DigitalSignature.sign((filename_digestI + filename_digestO).getBytes(),
                    RSA2048.constructPrivateKey(AppKeyPair.getPrivate()));

            //Επειτα η ψηφιακη υπγραφη αποθηκευεται σε αρχειο στον ιδιο φακελο με τα αρχεια του χρηστη
            FileWriter fw;
            BufferedWriter buff = new BufferedWriter(fw = new FileWriter(user_dir + "/" + signatureFileName));
            buff.write(Base64.getEncoder().encodeToString(sig));
            buff.close();
            fw.close();

            return 0;
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
            return Main.CORRUPTED_DATA_FILES;
        } catch (IOException ex) {
            ex.printStackTrace();
            return Main.CORRUPTED_DATA_FILES;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (SignatureException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        }
    }

    //Μεθοδος για τη επιβεβαιωση της ακεραιοτητας των αρχειων μεσω της ψηφιακης υπογραφης

    public static int verifyUserFiles(String username, String signatureFileName) {
        String user_dir = Main.USER_FILES_DIR_PATH + "/" + username;
        File user_income_file = new File(user_dir + "/" + "income.data");
        File user_outcome_file = new File(user_dir + "/" + "outcome.data");

        FileInputStream fis = null;
        try {
            //Οπως και πριν δημιουργουμε τις συνοψεις
            fis = new FileInputStream(user_income_file);
            byte[] data = new byte[(int) user_income_file.length()];
            fis.read(data);
            fis.close();
            byte[] digest = SHA256.Hash(data);
            String filename_digestI = "income.data" + Main.separator + Base64.getEncoder().encodeToString(data);

            fis = new FileInputStream(user_outcome_file);
            data = new byte[(int) user_outcome_file.length()];
            fis.read(data);
            fis.close();
            digest = SHA256.Hash(data);
            String filename_digestO = "outcome.data" + Main.separator + Base64.getEncoder().encodeToString(data);

            //Διαβαζουμε την υπογραφη απο το αρχειο (και την αποκωdikopoioyme στην συνεχεια απο Base64)
            fis = new FileInputStream(user_dir + "/" + signatureFileName);
            DataInputStream dis = new DataInputStream(fis);
            long len = new File(user_dir + "/" + signatureFileName).length();
            data = new byte[(int) len];
            dis.readFully(data);
            dis.close();
            
            //Γινεται η επιβεβαιωση των αρχειων με το δημοσιο κλειδι της εφαρμογης και τη υπογραφη
            boolean result = DigitalSignature.verify((filename_digestI + filename_digestO).getBytes(),
                    RSA2048.constructPublicKey(AppKeyPair.getPublic()),
                    Base64.getDecoder().decode(data));

            if (result) {
                return 0;
            } else {
                return Main.USER_FILES_INFRIGMENT;
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
            return Main.CORRUPTED_DATA_FILES;
        } catch (IOException ex) {
            ex.printStackTrace();
            return Main.CORRUPTED_DATA_FILES;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (SignatureException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
            return Main.ENCRYPTION_ERROR;
        }

    }
}
//Αυτη η κλαση αφορα καθαρα την ψηφιακη υπογραφη και περιεχει της μεθοδους για υπογραφης δεδομενων και επιβαιβεωση τους
class DigitalSignature {

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, PublicKey publicKey, byte[] signature) throws InvalidKeyException,
            IOException, SignatureException, FileNotFoundException, NoSuchAlgorithmException {

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
