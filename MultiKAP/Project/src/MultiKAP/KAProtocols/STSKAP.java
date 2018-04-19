package MultiKAP.KAProtocols;

import MultiKAP.CA.TrustStore;
import MultiKAP.Tools.CertTool;
import MultiKAP.Tools.EncryptionTool;
import MultiKAP.Tools.KeyTool;
import MultiKAP.Tools.SignatureTool;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public class STSKAP {

    private final Provider security_provider;

    private BigInteger P;
    private BigInteger G;
    private int L;

    //Υλοποιηση ενος σεναριου συμφωνιας κλειδιου αναμεσα σε δυο οντοτητες (Alice και Bob) βαση του πρωτόκολλου Station to Station
    public STSKAP () {

        this.security_provider = new BouncyCastleProvider();
        Security.setProperty("crypto.policy", "unlimited");

    }

    public void run (PrintStream out) {
        try {
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

            step++;//Δηνιουργια του ζευγους κλειδιων Diffie Hellman για την Alice
            //οπου δημοσιο ειναι το g^x και το ιδιωτικο το x

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates her DiffieHellman KeyPair using those parameters..."
                    + Ansi.SANE);

            DHParameterSpec DHparamsCommonA = new DHParameterSpec(P, G, L);
            KeyPair aliceKeys = KeyTool.generateKeyPair(DHparamsCommonA, "DiffieHellman", security_provider);

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

            step++;//"Αποστολη" των bytes του DHPublicKey της Alice στον Bob

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encodes her DHPublicKey (including the common DH parameters), and sends it to Bob..."
                    + Ansi.SANE);

            byte[] aliceEncodedPubKey = aliceKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's PublicKey Bytes" + Ansi.SANE);

            step++;//"Παραλαβη" των bytes του συμμετρικου κλειδιου της Alice απο τον Bob και ανακατασκευη σε DHPublicKey

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob receives Alice's encoded DHPublicKey and reconstructs it..."
                    + Ansi.SANE);

            DHPublicKey alicePubKey = (DHPublicKey) KeyTool.constructPublicKey(aliceEncodedPubKey, "DH", security_provider);
            out.println(Ansi.GREEN + "\nAlice's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(alicePubKey.getEncoded()));

            step++;//Ο Bob εξαγει τις παραμετρους του Diffie Hellman απο το κλειδι της Alice

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob gets the Common DiffieHellman Parameters Alice generated from her DHPublicKey.."
                    + Ansi.SANE);

            DHParameterSpec DHparamsCommonB = alicePubKey.getParams();
            out.println(Ansi.GREEN + "\n\tDiffieHellman parameters from key:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nP: " + Ansi.SANE + DHparamsCommonB.getP()
                    + Ansi.YELLOW + "\n\nG: " + Ansi.SANE + DHparamsCommonB.getG()
                    + Ansi.YELLOW + "\n\nL: " + Ansi.SANE + DHparamsCommonB.getL());

            step++; //Δηνιουργια του ζευγους κλειδιων Diffie Hellman για τον Bob
            //οπου δημοσιο ειναι το g^y και το ιδιωτικο το y

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates his DiffieHellman KeyPair using those parameters..."
                    + Ansi.SANE);

            KeyPair bobKeys = KeyTool.generateKeyPair(DHparamsCommonB, "DiffieHellman", security_provider);
            out.println(Ansi.GREEN + "\n\tBob's KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\n\nBob's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nBob's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPrivate().getEncoded()));

            step++;//Αρχικοποιηση του KeyAgreement με το ιδιωτικο κλειδι του που δημιουργησε (οι παραμετροι του  Diffie Hellman υπαρχουν σε αυτο)

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob initializes his DiffieHellman KeyAgreement with his private key..."
                    + Ansi.SANE);

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DiffieHellman", security_provider);
            bobKeyAgree.init(bobKeys.getPrivate());
            out.println(Ansi.GREEN + "\n\tBob's " + bobKeyAgree.getAlgorithm() + " KeyAgreement initialized" + Ansi.SANE);

            step++; //Δημιουργια του SecretKey που θα χρησιμοποιησουν απο τη KeyAgreement το οποιο αρχικοποειται με το δημοσιο κλειδι του Bob
            //K = g^x^y mod p

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates the Common Secret Key using Alice's public key and his private key..."
                    + Ansi.SANE);

            bobKeyAgree.doPhase(alicePubKey, true); //true γιατι ειναι (πρωτη και) τελευταια φαση του πρωτοκολλου
            byte[] bobEncodedSecretKey = bobKeyAgree.generateSecret();
            SecretKey bobSecretKey = KeyTool.constructKey(bobEncodedSecretKey, 256, "AES"); //32 bytes -> 256 bits

            out.println(Ansi.GREEN + "\n\tBob's Common SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobSecretKey.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobSecretKey.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + bobSecretKey.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nBob's Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSecretKey.getEncoded()));

            step++;//Δηνιουργια του ζευγους κλειδιων RSA για το πιστοποιητικο του Bob
            //μηκους 2048

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates a pair of RSA keys (for his signature)..."
                    + Ansi.SANE);
            KeyPair bobRSAKeys = KeyTool.generateKeyPair(2048, "RSA", security_provider);
            out.println(Ansi.GREEN + "\n\tBob's RSA KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobRSAKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobRSAKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\nPublic Key Size: " + Ansi.SANE + bobRSAKeys.getPublic().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\nPrivate Key Size: " + Ansi.SANE + bobRSAKeys.getPrivate().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nBob's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobRSAKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nBob's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobRSAKeys.getPrivate().getEncoded()));

            step++; //Δημιουργια του πιστοποιητικου του Bob που υπογραφεται απο τη CA και περιεχει το ονομα του το δημοσιο κλειδι του και τις παραμετρους g και x του Diffie Hellman που χρησιμοποιησε

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates a X509 Certificate Signed by the CA including his name, his RSA public key and the common DH parameters..."
                    + Ansi.SANE);
            //Δημιουργια certification request (PKCS10CertificationRequest) με τις καταλληλες επεκτασεις και δημιουργια του X509 πιστοποιητικου βαση αυτου
            PKCS10CertificationRequest bobCR = CertTool.generateRequest("Bob", bobRSAKeys.getPublic(), DHparamsCommonB, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"),
                                                                        security_provider);
            X509Certificate bobCert = CertTool.getCertificate(bobCR, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Certificate generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + bobCert.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + bobCert.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + bobCert.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + bobCert.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(bobCert.getEncoded()));

            step++; //Δημιουργια ψηφιακης υπογραφης του Bob πανω στο δημοσιο κλειδι του και της Alice η οποια περιεχει και το πιστοποιητικο του

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob signs his and Alice's DH public keys with his DH private key (including his certificate)..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesB = concatBytes(bobKeys.getPublic().getEncoded(), alicePubKey.getEncoded());
            byte[] bobSign = SignatureTool.sign(DHPubKeysBytesB, bobRSAKeys.getPrivate(), bobCert, TrustStore.getCAcert("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Signature generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nSignature Algorithm: " + SignatureTool.algorithm
                    + Ansi.YELLOW + "\n\nBob's Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSign));

            step++; //Ο Bob κρυπτογραφει τη ψηφιακη υπογραφη με το συμμετρικο κλειδι του με AES σε ECB mode (χωρις iv)

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob encrypts his signature with the Common Secret Key, using AES in ECB mode..."
                    + Ansi.SANE);

            byte[] bobEncryptedSig = EncryptionTool.Encrypt(bobSign, bobSecretKey, "AES", false, security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Signature encrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nEncrypted Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobEncryptedSig));

            step++; //Ο Bob "αποστελει" στην Alice τα bytes του δημοσιου κλειδιου του και την κρυπτογραφημενη υπογραφη του πανω στα δημοσια κλειδια τους

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob sends his encoded DH public key and his encrypted signature of the DH public keys (including his certificate) to Alice..."
                    + Ansi.SANE);
            byte[] bobEncodedPubKey = bobKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tBob -> Alice: Bob's PublicKey Bytes, Bob's Signature" + Ansi.SANE);

            step++; //Η Alice "λαμβανει" τα bytes του δημοσιου κλειδιου του Bob και τη κρυπτογραφημενη του υπογραφη

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice receives Bob's signature and encoded DH public key and reconstructs it..."
                    + Ansi.SANE);

            DHPublicKey bobPubKey = (DHPublicKey) KeyTool.constructPublicKey(bobEncodedPubKey, "DH", security_provider);
            out.println(Ansi.GREEN + "\n\tBob's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's Public Key:"
                    + Ansi.SANE + "\n" + Base64.toBase64String(bobPubKey.getEncoded()));

            step++; //Δημιουργια του SecretKey που θα χρησιμοποιησουν απο τη KeyAgreement το οποιο αρχικοποειται με το δημοσιο κλειδι του Bob
            //K = g^y^x mod p

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates the Common Secret Key usgin Bob's public key and her private key..."
                    + Ansi.SANE);

            aliceKeyAgree.doPhase(bobPubKey, true);
            byte[] aliceEncodedSecretKey = aliceKeyAgree.generateSecret();
            SecretKey aliceSecretKey = KeyTool.constructKey(aliceEncodedSecretKey, 256, "AES");

            out.println(Ansi.GREEN + "\n\tAlice's Common SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceSecretKey.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceSecretKey.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + aliceSecretKey.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nAlice's Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceSecretKey.getEncoded()));

            step++; //Η Alice αποκρυπτογραφει τη ψηφιακη υπογραφη του Bob και εξαγει απο αυτη το πιστοποιητικο του Bob

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice decrypts the signature using the same algorithm and mode and extracts Bob's Certificate..."
                    + Ansi.SANE);

            byte[] aliceDecryptedSigB = EncryptionTool.Decrypt(bobEncryptedSig, aliceSecretKey, "AES", false, security_provider);

            X509Certificate aliceCertBob = SignatureTool.getCertificate(aliceDecryptedSigB, security_provider);

            System.out.println(CertTool.getExtensionValue(aliceCertBob, CertTool.OID_P));
            out.println(Ansi.GREEN + "\n\tBob's signature decrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's Decrypted signature: " + Ansi.SANE + Base64.toBase64String(aliceDecryptedSigB)
                    + Ansi.YELLOW + "\n\n\tBob's certificate extracted: " + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + aliceCertBob.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + aliceCertBob.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + aliceCertBob.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + aliceCertBob.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceCertBob.getEncoded()));

            step++; //H Alice επιβεβαιωνει το πιστοποιητικο του Bob (οτι ειναι υπογεγραμενο απο τη κοινη CA και ισχυει),
            //τις παραμετρους του DH που υπαρχουν στο πιστοποιητικο
            //και την υπογραφη του πανω στα κλειδια με το δικο της δημοσιο κλειδι και αυτο που παρελαβε

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice verifies Bob's signature over her and his DH public keys and that the DH parameters included in his certificate are those she sent him..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesBA = concatBytes(bobPubKey.getEncoded(), alicePubKey.getEncoded());

            boolean checkBobSig = SignatureTool.verify(DHPubKeysBytesBA, bobSign, security_provider);
            boolean checkBobCert = false;
            try {
                aliceCertBob.verify(TrustStore.getCAcert("MultiKAP").getPublicKey(), security_provider);
                aliceCertBob.checkValidity();
                checkBobCert = true;
            } catch (Exception e) {
            }
            String bobG = CertTool.getExtensionValue(aliceCertBob, CertTool.OID_G);
            String bobP = CertTool.getExtensionValue(aliceCertBob, CertTool.OID_P);
            boolean checkBobDHParams = bobG.equals(DHparamsCommonA.getG().toString()) && bobP.equals(DHparamsCommonA.getP().toString());

            out.println(Ansi.GREEN + "\n\tVerification Results:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's signature verified: " + Ansi.SANE + checkBobSig
                    + Ansi.YELLOW + "\nBob's certificate verified: " + Ansi.SANE + checkBobCert
                    + Ansi.YELLOW + "\nBob's DH parameters verified: " + Ansi.SANE + checkBobDHParams);

            if (!checkBobSig || !checkBobDHParams || !checkBobCert) {
                System.exit(1);
            }

            step++; //H Alice δημιουργει ενα ζευγος κλειδιων RSA μηκους 2048 bits για το πιστοποιητικο της

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates a pair of RSA keys (for her signature)..."
                    + Ansi.SANE);
            KeyPair aliceRSAKeys = KeyTool.generateKeyPair(2048, "RSA", security_provider);
            out.println(Ansi.GREEN + "\n\tAlice's RSA KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceRSAKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceRSAKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\nPublic Key Size: " + Ansi.SANE + aliceRSAKeys.getPublic().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\nPrivate Key Size: " + Ansi.SANE + aliceRSAKeys.getPrivate().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nBob's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceRSAKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nBob's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceRSAKeys.getPrivate().getEncoded()));

            step++; //Δημιουργια του πιστοποιητικου της Alice που υπογραφεται απο τη CA και περιεχει το ονομα του το δημοσιο κλειδι της και τις παραμετρους g και x του Diffie Hellman που χρησιμοποιησε

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates a X509 Certificate Signed by the CA including her name, her RSA public key and the common DH parameters..."
                    + Ansi.SANE);

            //Δημιουργια certification request (PKCS10CertificationRequest) με τις καταλληλες επεκτασεις και δημιουργια του X509 πιστοποιητικου βαση αυτου
            PKCS10CertificationRequest aliceCR = CertTool.generateRequest("Alice", aliceRSAKeys.getPublic(), DHparamsCommonA, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"),
                                                                          security_provider);
            X509Certificate aliceCert = CertTool.getCertificate(aliceCR, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Certificate generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + aliceCert.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + aliceCert.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + aliceCert.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + aliceCert.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(bobCert.getEncoded()));

            step++; //Δημιουργια ψηφιακης υπογραφης της Alice πανω στο δημοσιο κλειδι της και του Bob η οποια περιεχει και το πιστοποιητικο του

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice signs her and Bob's DH public keys with her DH private key (including her certificate)..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesA = concatBytes(alicePubKey.getEncoded(), bobPubKey.getEncoded());
            byte[] aliceSign = SignatureTool.sign(DHPubKeysBytesA, aliceRSAKeys.getPrivate(), aliceCert, TrustStore.getCAcert("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tAlice's Signature generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nSignature Algorithm: " + SignatureTool.algorithm
                    + Ansi.YELLOW + "\n\nAlice's Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSign));

            step++; //H Alice κρυπτογραφει τη ψηφιακη υπογραφη με το συμμετρικο κλειδι του με AES σε ECB mode (χωρις iv)

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encrypts her signature with the Common Secret Key, using AES in ECB mode with PKCS#5 Padding..."
                    + Ansi.SANE);

            byte[] aliceEncryptedSig = EncryptionTool.Encrypt(aliceSign, aliceSecretKey, "AES", false, security_provider);

            out.println(Ansi.GREEN + "\n\tAlice's Signature encrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nEncrypted Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceEncryptedSig));

            step++; //H Alice "αποστελει" στoν Bob τα bytes του δημοσιου κλειδιου της και την κρυπτογραφημενη υπογραφη της πανω στα δημοσια κλειδια τους

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice sends her encrypted signature of the DH public keys (including her certificate) to Bob..."
                    + Ansi.SANE);
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's Signature" + Ansi.SANE);

            step++; //O Bob "λαμβανει" τη κρυπτογραφημενη υπογραφη της Alice και την αποκρυπτογραφei με το συμμετρικο κλειδι του και εξαγει απο αυτη το πιστοποιητικο της Alice

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob receives and decrypts Alice's signature using the same algorithm, mode and padding and extracts her Certificate..."
                    + Ansi.SANE);

            byte[] bobDecryptedSigA = EncryptionTool.Decrypt(aliceEncryptedSig, bobSecretKey, "AES", false, security_provider);

            X509Certificate bobCertAlice = SignatureTool.getCertificate(bobDecryptedSigA, security_provider);

            out.println(Ansi.GREEN + "\n\tAlice's signature decrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's Decrypted signature: " + Ansi.SANE + Base64.toBase64String(bobDecryptedSigA)
                    + Ansi.YELLOW + "\n\n\tAlice's certificate extracted: " + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + bobCertAlice.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + bobCertAlice.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + bobCertAlice.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + bobCertAlice.getNotAfter()
                    + Ansi.YELLOW + "\n\nAlice's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(bobCertAlice.getEncoded()));

            step++; //Ο Bob επιβεβαιωνει το πιστοποιητικο της Alice (οτι ειναι υπογεγραμενο απο τη κοινη CA και ισχυει),
            //τις παραμετρους του DH που υπαρχουν στο πιστοποιητικο
            //και την υπογραφη thw πανω στα κλειδια με το δικο toy δημοσιο κλειδι και αυτο που παρελαβε

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob verifies Alice's signature over his and her DH public keys and that the DH parameters included in her certificate are those she sent him..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesAB = concatBytes(alicePubKey.getEncoded(), bobKeys.getPublic().getEncoded());

            boolean checkAliceSig = SignatureTool.verify(DHPubKeysBytesAB, aliceSign, security_provider);
            boolean checkAliceCert = false;
            try {
                bobCertAlice.verify(TrustStore.getCAcert("MultiKAP").getPublicKey(), security_provider);
                bobCertAlice.checkValidity();
                checkAliceCert = true;
            } catch (Exception e) {
            }
            String aliceG = CertTool.getExtensionValue(bobCertAlice, CertTool.OID_G);
            String aliceP = CertTool.getExtensionValue(bobCertAlice, CertTool.OID_P);
            boolean checkAliceDHParams = aliceG.equals(DHparamsCommonB.getG().toString()) && aliceP.equals(DHparamsCommonB.getP().toString());
            out.println(Ansi.GREEN + "\n\tVerification Results:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's signature verified: " + Ansi.SANE + checkAliceSig
                    + Ansi.YELLOW + "\nAlice's certificate verified: " + Ansi.SANE + checkAliceCert
                    + Ansi.YELLOW + "\nAlice's DH parameters verified: " + Ansi.SANE + checkAliceDHParams);

            if (!checkAliceSig || !checkAliceDHParams || !checkAliceCert) {
                System.exit(1);
            }

            step++; //H Alice κρυπτογραφει συμμετρικα ενα μηνυμα με το SecretKey της χρησιμοποιωντας AES με CBC

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encrypts with the Common Secret Key, using AES in CBC mode with PKCS#5 Padding, a message then encodes it and sends it to Bob..."
                    + Ansi.SANE);

            byte[] m = EncryptionTool.Encrypt("This is ma big secret".getBytes(), aliceSecretKey, "AES/CBC/PKCS5Padding", true, security_provider);

            out.println(Ansi.GREEN + "\nAlice -> Bob: [encrypted message encoded]" + Ansi.SANE);

            step++; //O Bob "παραλαμβανει" και αποκρυπτογραφει με SecretKey του το κρυπτογραφημα χρησιμοποιωντας AES με CBC

            out.println(
                    "\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob decrypts with the Common Secret Key, using the same algorithm, mode and padding, the encrypted message Alice sent him..."
                    + Ansi.SANE);

            byte[] Dm = EncryptionTool.Decrypt(m, bobSecretKey, "AES/CBC/PKCS5Padding", true, security_provider);
            out.println(Ansi.YELLOW + "\nDecrypted message: "
                    + Ansi.SANE + new String(Dm) + "\n");

        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException |
                 OperatorCreationException | KeyStoreException | CertificateException |
                 InvalidAlgorithmParameterException | IOException |
                 UnrecoverableKeyException | NoSuchProviderException | CMSException | SignatureException ex) {
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

    //Συμπηκνωση δυο byte array σε ενα τριτο
    public byte[] concatBytes (byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
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
