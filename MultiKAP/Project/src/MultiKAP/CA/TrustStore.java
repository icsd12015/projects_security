package MultiKAP.CA;

import static MultiKAP.Tools.CertTool.getSelfSignedCertificate;
import MultiKAP.Tools.KeyTool;
import MultiKAP.Tools.PemFileTool;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
/**
 * @author icsd12015 *
 */
//Περοιέχει μεθόδους για τη ανακτηση του ιδιωτικου κλειδιου και του πιστοποιητικου της CA απο το trusted keystore
public class TrustStore {

    //Το path του trusted KeyStore και ο κωδικος του
    private final static File keystore_file = new File("TrustStore\\TrustStore.jks");
    private final static String keystore_password = "xtakis+nikos";
    //Για την αποθηκευση του πιστοποιητικου
    private final static File cert_file = new File("TrustStore\\MultiKAP.crt");

    private final static Provider bcprov = new BouncyCastleProvider();

    //Μεθοδος για φορτωση του ιδιωτικου κλειδιου της CA απο το αρχειο keystore βαση του alias της
    public static PrivateKey getCAprivateKey (String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException,
                                                                   CertificateException, UnrecoverableKeyException {
        //Φορτωση του KeyStore απο το αρχειο
        FileInputStream input = new FileInputStream(keystore_file);
        KeyStore getkeystore = KeyStore.getInstance("BKS", bcprov);
        getkeystore.load(input, keystore_password.toCharArray());

        return (PrivateKey) getkeystore.getKey(alias, keystore_password.toCharArray());
    }

    //Μεθοδος για φορτωση του πιστοποιητικου της CA απο το αρχειο keystore βαση του alias της
    public static X509Certificate getCAcert (String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException,
                                                                  CertificateException, UnrecoverableKeyException {
        //Φορτωση του KeyStore απο το αρχειο
        FileInputStream input = new FileInputStream(keystore_file);
        KeyStore keystore = KeyStore.getInstance("BKS", bcprov);
        keystore.load(input, keystore_password.toCharArray());

        return (X509Certificate) keystore.getCertificate(alias);
    }

    //Δημιουργια του ζευγους RSA κλειδιων και του ανθυπογραφου πιστοποιηκου εφαρμογης (PassManager CA)
    // και KeyStore στο οποιο φορτωνονται τα παραπανω και επειτα αποθηκευεται σε αρχειο
    public static void main (String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException,
                                                   OperatorCreationException, KeyStoreException {
        
        Security.setProperty("crypto.policy", "unlimited");
        
        //Δημιουργια PemWriter με για το stream του output console για εμφανιση των κλειδιων και του πιστοποιηκου στην οθονη
        PemWriter conPemWriter = new PemWriter(new PrintWriter(System.out));

        //Δημιουργια του ζευγους RSA κλειδιων με μηκος 2048
        KeyPair CAkeys = KeyTool.generateKeyPair(2048, "RSA", bcprov);
        //Δημιουργια του ανθυπογραφου πιστοποιηκου
        X509Certificate CAcert = getSelfSignedCertificate(CAkeys, "MultiKAP CA", "Χρήστος Αυλακιώτης 321|2012015 - Νίκος Τρίτσης 321|2011162", bcprov);

        //Δημιουργια PemObject για αυτα ωστε να τυπωθουν στην οθονη με τον PemWriter
        PemObject privateCAkeyPEM = new PemObject("RSA PRIVATE KEY", CAkeys.getPrivate().getEncoded());
        PemObject publicCAkeyPEM = new PemObject("RSA PUBLIC KEY", CAkeys.getPublic().getEncoded());
        PemObject CAcertPEM = new PemObject("X.509 CERTIFICATE", CAcert.getEncoded());

        //Τυπωμα των PemObject αυτων  στην οθονη με τον PemWriter
        conPemWriter.writeObject(privateCAkeyPEM);
        conPemWriter.writeObject(publicCAkeyPEM);
        conPemWriter.writeObject(CAcertPEM);
        conPemWriter.flush();

        //Δημιουργια KeyStore
        KeyStore keyStore = KeyStore.getInstance("BKS", bcprov);
        keyStore.load(null, keystore_password.toCharArray());

        //Αποθηκευση του πιστοποιητικου στο keystore
        keyStore.setCertificateEntry(
                "MultiKAP",
                CAcert);
        //Αποθηκευση του ιδιωτικου κλειδιου στο keystore
        keyStore.setKeyEntry(
                "MultiKAP",
                CAkeys.getPrivate(),
                keystore_password.toCharArray(),
                new X509Certificate[]{CAcert});
        //Δε δημιουργειται entry για το δημοσιο κλειδι στο keystore καθως εμπεριεχεται στο πιστοποιητικο

        PemFileTool.write("MultiKAP CA X.509 Certificate", CAcert.getEncoded(), cert_file.getPath());
        //
        //Αποθηκευση του keystore σε αρχειο
        FileOutputStream output = new FileOutputStream(keystore_file);
        keyStore.store(output, keystore_password.toCharArray());
    }
}
