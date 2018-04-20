package Security;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
/**
 * @author icsd12015 *
 */
//Περιέχει μεθοδους για εγγραφη πιστοποιητικων και κλειδιων σε αρχεια με τον PemWrite της Bouncy Castle
public class PemFileTool {

    //Μεθοδος για την εγγραφη ενος αντικειμενου σε ενα αρχειο με τον PemWriter δεδομενου της περιγραφης του, των bytes και του ονοματος για το αρχειο
    public static void write (String description, byte[] bytes, String filename) throws FileNotFoundException, IOException {

        File outfile = new File(filename);

        if (!outfile.exists()) {
            outfile.createNewFile();
        }

        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)))) {
            PemObject pem = new PemObject(description, bytes);
            pemWriter.writeObject(pem);
            EncodedKeySpec k;
        }
    }

    //Μεθοδος για το διαβασμα ενος αντικειμενου απο ενα αρχειο με τον PemReader δεδομενου του ονοματος του αρχειου
    public static PemObject read (String filename) throws FileNotFoundException, IOException {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)))) {
            PemObject pem = pemReader.readPemObject();
            return pem;
        }
    }

    //Μεθοδος για το διαβασμα και κατασκευη ενος X.509 certificate απο ενα αρχειο
    //http://www.programcreek.com/java-api-examples/index.php?source_dir=usc-master/usc-channel-impl/src/main/java/org/opendaylight/usc/crypto/dtls/DtlsUtils.java
    public static X509Certificate loadCertificate (String filename, String type, Provider provider) throws IOException, CertificateException, NoSuchProviderException {
        PemObject pem = read(filename);
        if (pem.getType().endsWith("Χ.509 CERTIFICATE")) {
            CertificateFactory cf = CertificateFactory.getInstance(type, provider);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(pem.getContent()));
        }
        throw new IllegalArgumentException(filename + " doesn't specify a valid certificate");
    }

    //Πηγη: https://stackoverflow.com/questions/11787571/how-to-read-pem-file-to-get-private-and-public-key
    //
    //Μεθοδος για το διαβασμα και κατασκευη ενος ιδιωτικου κλειδιου απο ενα αρχειο
    public static PrivateKey loadPrivateKey (String filename, String algorithm, Provider provider) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
                                                                                                          NoSuchProviderException {
        PemObject pem = read(filename);
        if (pem.getType().endsWith("RSA PRIVATE KEY")) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pem.getContent());
            KeyFactory kf = KeyFactory.getInstance(algorithm, provider);
            return kf.generatePrivate(spec);
        }
        throw new IllegalArgumentException(filename + filename + " doesn't specify a valid private key");
    }

    //Μεθοδος για το διαβασμα και κατασκευη ενος δημοσιου κλειδιου απο ενα αρχειο
    public static PublicKey loadPublicKey (String filename, String algorithm, Provider provider) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
                                                                                                        NoSuchProviderException {
        PemObject pem = read(filename);
        if (pem.getType().endsWith("RSA PUBLIC KEY")) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pem.getContent());
            KeyFactory kf = KeyFactory.getInstance(algorithm, provider);
            return kf.generatePublic(spec);
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
    }

    public static SecretKey loadSecretKey (String filename, String algorithm, Provider provider) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
                                                                                                        NoSuchProviderException {
        PemObject pem = read(filename);
        return new SecretKeySpec(pem.getContent(), 0, pem.getContent().length, algorithm);
    }
}
