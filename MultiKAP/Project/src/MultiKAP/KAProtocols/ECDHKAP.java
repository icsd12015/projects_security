package MultiKAP.KAProtocols;

import MultiKAP.CA.TrustStore;
import MultiKAP.Tools.*;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public class ECDHKAP {

    private final Provider security_provider;

    public ECDHKAP () {

        this.security_provider = new BouncyCastleProvider();
        Security.setProperty("crypto.policy", "unlimited");

    }

    //Υλοποιηση ενος σεναριου συμφωνιας κλειδιου αναμεσα σε δυο οντοτητες (Alice και Bob) βαση της ενδυναμωμενης εκδοχης του πρωτόκολλου Station to Station
    //Για την ενδυναμωση γινεται χρηση Elliptic Curve για τις παραμετρους και τα κλειδια του Diffie Hellman
    //Στα πιστοποιητικα αυτη τη φορα προστιθονται ως επεκτασεις οι παραμετροι a και b της καμπυλης
    public void run (PrintStream out) {
        try {
            int step = 0;
            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates her DiffieHellman KeyPair using Elliptic Curve for the generation of DH parameters..."
                    + Ansi.SANE);

            KeyPair aliceKeys = KeyTool.generateKeyPair(256, "EC", security_provider);
            ECParameterSpec ECDHparamsCommonA = ((ECPublicKey) aliceKeys.getPublic()).getParameters();

            out.println(Ansi.GREEN + "\n\tAlice's KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + aliceKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + aliceKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\nPublic Key Size: " + Ansi.SANE + aliceKeys.getPublic().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\nPrivate Key Size: " + Ansi.SANE + aliceKeys.getPrivate().getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nAlice's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceKeys.getPrivate().getEncoded()));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice initializes her DiffieHellman KeyAgreement instance with her private key..."
                    + Ansi.SANE);

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH", security_provider);
            aliceKeyAgree.init(aliceKeys.getPrivate());
            out.println(Ansi.GREEN + "\n\tAlice's " + aliceKeyAgree.getAlgorithm() + " KeyAgreement initialized" + Ansi.SANE);

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encodes her DHPublicKey (including the common DH parameters), and sends it to Bob..."
                    + Ansi.SANE);

            byte[] aliceEncodedPubKey = aliceKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's PublicKey Bytes" + Ansi.SANE);

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob receives Alice's encoded DHPublicKey and reconstructs it..."
                    + Ansi.SANE);

            BCECPublicKey alicePubKey = (BCECPublicKey) KeyTool.constructPublicKey(aliceEncodedPubKey, "EC", security_provider);
            out.println(Ansi.GREEN + "\nAlice's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(alicePubKey.getEncoded()));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob gets the Common DiffieHellman Parameters Alice generated from her DHPublicKey.."
                    + Ansi.SANE);

            ECParameterSpec ECDHparamsCommonB = ((ECPublicKey) aliceKeys.getPublic()).getParameters();
            out.println(Ansi.GREEN + "\n\tDiffieHellman parameters from key:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nCurve's A: " + Ansi.SANE + ECDHparamsCommonB.getCurve().getA()
                    + Ansi.YELLOW + "\n\nCurve's B: " + Ansi.SANE + ECDHparamsCommonB.getCurve().getB()
                    + Ansi.YELLOW + "\n\nG: " + Ansi.SANE + ECDHparamsCommonB.getG()
                    + Ansi.YELLOW + "\n\nN: " + Ansi.SANE + ECDHparamsCommonB.getN());

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates his DiffieHellman KeyPair using those parameters..."
                    + Ansi.SANE);

            KeyPair bobKeys = KeyTool.generateKeyPair(ECDHparamsCommonB, "ECDH", security_provider);
            out.println(Ansi.GREEN + "\n\tBob's KeyPair generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobKeys.getPrivate().getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobKeys.getPrivate().getFormat()
                    + Ansi.YELLOW + "\n\nBob's Public Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPublic().getEncoded())
                    + Ansi.YELLOW + "\n\nBob's Private Key:" + Ansi.SANE + "\n" + Base64.toBase64String(bobKeys.getPrivate().getEncoded()));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob initializes his DiffieHellman KeyAgreement with his private key..."
                    + Ansi.SANE);

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH", security_provider);
            bobKeyAgree.init(bobKeys.getPrivate());
            out.println(Ansi.GREEN + "\n\tBob's " + bobKeyAgree.getAlgorithm() + " KeyAgreement initialized" + Ansi.SANE);

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates the Common Secret Key using Alice's public key and his private key..."
                    + Ansi.SANE);

            bobKeyAgree.doPhase(alicePubKey, true);
            byte[] bobEncodedSecretKey = bobKeyAgree.generateSecret();
            SecretKey bobSecretKey = KeyTool.constructKey(bobEncodedSecretKey, 256, "AES");

            out.println(Ansi.GREEN + "\n\tBob's Common SecretKey generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlgorithm: " + Ansi.SANE + bobSecretKey.getAlgorithm()
                    + Ansi.YELLOW + "\nFormat: " + Ansi.SANE + bobSecretKey.getFormat()
                    + Ansi.YELLOW + "\nSize: " + Ansi.SANE + bobSecretKey.getEncoded().length * 8 + " bits"
                    + Ansi.YELLOW + "\n\nBob's Common SecretKey:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSecretKey.getEncoded()));

            step++;

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

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob generates a X509 Certificate Signed by the CA including his name, his RSA public key and the common DH parameters..."
                    + Ansi.SANE);
            PKCS10CertificationRequest bobCR = CertTool.generateRequest("Bob", bobRSAKeys.getPublic(), ECDHparamsCommonB,
                                                                        TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);
            //Δημιουργια του πιστοποιητικου του Bob που υπογραφεται απο τη CA και περιεχει το ονομα του το δημοσιο κλειδι του και τις παραμετρους a και b για την ελληπτικη καμπυλη γα τις παραμετρους του Diffie Hellman που χρησιμοποιησε
            X509Certificate bobCert = CertTool.getCertificate(bobCR, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);
            out.println(Ansi.GREEN + "\n\tBob's Certificate generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + bobCert.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + bobCert.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + bobCert.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + bobCert.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(bobCert.getEncoded()));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob signs his and Alice's DH public keys with his DH private key (including his certificate)..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesB = concatBytes(bobKeys.getPublic().getEncoded(), alicePubKey.getEncoded());
            byte[] bobSign = SignatureTool.sign(DHPubKeysBytesB, bobRSAKeys.getPrivate(), bobCert, TrustStore.getCAcert("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Signature generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nSignature Algorithm: " + SignatureTool.algorithm
                    + Ansi.YELLOW + "\n\nBob's Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSign));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob encrypts his signature with the Common Secret Key, using AES in ECB mode with PKCS#5 Padding..."
                    + Ansi.SANE);

            byte[] bobEncryptedSig = EncryptionTool.Encrypt(bobSign, bobSecretKey, "AES", false, security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Signature encrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nEncrypted Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobEncryptedSig));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob sends his encoded DH public key and his encrypted signature of the DH public keys (including his certificate) to Alice..."
                    + Ansi.SANE);
            byte[] bobEncodedPubKey = bobKeys.getPublic().getEncoded();
            out.println(Ansi.GREEN + "\n\tBob -> Alice: Bob's PublicKey Bytes, Bob's Signature" + Ansi.SANE);

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice receives Bob's signature and encoded DH public key and reconstructs it..."
                    + Ansi.SANE);

            BCECPublicKey bobPubKey = (BCECPublicKey) KeyTool.constructPublicKey(bobEncodedPubKey, "EC", security_provider);
            out.println(Ansi.GREEN + "\n\tBob's PublicKey reconstructed:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's Public Key:"
                    + Ansi.SANE + "\n" + Base64.toBase64String(bobPubKey.getEncoded()));

            step++;

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

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice decrypts the signature using the same algorithm, mode and padding and extracts Bob's Certificate..."
                    + Ansi.SANE);

            byte[] aliceDecryptedSigB = EncryptionTool.Decrypt(bobEncryptedSig, aliceSecretKey, "AES", false, security_provider);

            X509Certificate aliceCertBob = SignatureTool.getCertificate(aliceDecryptedSigB, security_provider);

            out.println(Ansi.GREEN + "\n\tBob's signature decrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's Decrypted signature: " + Ansi.SANE + Base64.toBase64String(aliceDecryptedSigB)
                    + Ansi.YELLOW + "\n\n\tBob's certificate extracted: " + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + aliceCertBob.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + aliceCertBob.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + aliceCertBob.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + aliceCertBob.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceCertBob.getEncoded()));

            step++;

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
            String bobA = CertTool.getExtensionValue(aliceCertBob, CertTool.OID_A);
            String bobB = CertTool.getExtensionValue(aliceCertBob, CertTool.OID_B);
            System.out.println(bobA);
            System.out.println(ECDHparamsCommonA.getCurve().getB().toString());
            boolean checkBobDHParams = bobA.equals(ECDHparamsCommonA.getCurve().getA().toBigInteger().toString()) && bobB.equals(ECDHparamsCommonA.getCurve().getB().toBigInteger().toString());
            out.println(Ansi.GREEN + "\n\tVerification Results:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nBob's signature verified: " + Ansi.SANE + checkBobSig
                    + Ansi.YELLOW + "\nBob's certificate verified: " + Ansi.SANE + checkBobCert
                    + Ansi.YELLOW + "\nBob's DH parameters verified: " + Ansi.SANE + checkBobDHParams);

            if (!checkBobSig || !checkBobDHParams || !checkBobCert) {
                System.exit(1);
            }

            step++;

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

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice generates a X509 Certificate Signed by the CA including her name, her RSA public key and the common DH parameters..."
                    + Ansi.SANE);
            PKCS10CertificationRequest aliceCR = CertTool.generateRequest("Alice", aliceRSAKeys.getPublic(), ECDHparamsCommonA,
                                                                          TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);
            X509Certificate aliceCert = CertTool.getCertificate(aliceCR, TrustStore.getCAcert("MultiKAP"), TrustStore.getCAprivateKey("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tBob's Certificate generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nType: " + Ansi.SANE + aliceCert.getType()
                    + Ansi.YELLOW + "\nIssuer: " + Ansi.SANE + aliceCert.getIssuerDN()
                    + Ansi.YELLOW + "\nIssued to: " + Ansi.SANE + aliceCert.getSubjectX500Principal()
                    + Ansi.YELLOW + "\nExpiration: " + Ansi.SANE + aliceCert.getNotAfter()
                    + Ansi.YELLOW + "\n\nBob's Certificate:" + Ansi.SANE + "\n" + Base64.toBase64String(bobCert.getEncoded()));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice signs her and Bob's DH public keys with her DH private key (including her certificate)..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesA = concatBytes(alicePubKey.getEncoded(), bobPubKey.getEncoded());
            byte[] aliceSign = SignatureTool.sign(DHPubKeysBytesA, aliceRSAKeys.getPrivate(), aliceCert, TrustStore.getCAcert("MultiKAP"), security_provider);

            out.println(Ansi.GREEN + "\n\tAlice's Signature generated:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nSignature Algorithm: " + SignatureTool.algorithm
                    + Ansi.YELLOW + "\n\nAlice's Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(bobSign));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encrypts her signature with the Common Secret Key, using AES in ECB mode with PKCS#5 Padding..."
                    + Ansi.SANE);

            byte[] aliceEncryptedSig = EncryptionTool.Encrypt(aliceSign, aliceSecretKey, "AES", false, security_provider);

            out.println(Ansi.GREEN + "\n\tAlice's Signature encrypted:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nEncrypted Signature:" + Ansi.SANE + "\n" + Base64.toBase64String(aliceEncryptedSig));

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice sends her encrypted signature of the DH public keys (including her certificate) to Bob..."
                    + Ansi.SANE);
            out.println(Ansi.GREEN + "\n\tAlice -> Bob: Alice's Signature" + Ansi.SANE);

            step++;

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

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Bob verifies Alice's signature over his and her DH public keys and that the DH parameters included in her certificate are those she sent him..."
                    + Ansi.SANE);

            byte[] DHPubKeysBytesAΒ = concatBytes(alicePubKey.getEncoded(), bobKeys.getPublic().getEncoded());

            boolean checkAliceSig = SignatureTool.verify(DHPubKeysBytesAΒ, aliceSign, security_provider);
            boolean checkAliceCert = false;
            try {
                bobCertAlice.verify(TrustStore.getCAcert("MultiKAP").getPublicKey(), security_provider);
                bobCertAlice.checkValidity();
                checkAliceCert = true;
            } catch (Exception e) {
            }
            String aliceA = CertTool.getExtensionValue(bobCertAlice, CertTool.OID_A);
            String aliceB = CertTool.getExtensionValue(bobCertAlice, CertTool.OID_B);
            boolean checkAliceDHParams = aliceA.equals(ECDHparamsCommonB.getCurve().getA().toBigInteger().toString()) && aliceB.equals(ECDHparamsCommonB.getCurve().getB().toBigInteger().toString());
            out.println(Ansi.GREEN + "\n\tVerification Results:" + Ansi.SANE
                    + Ansi.YELLOW + "\n\nAlice's signature verified: " + Ansi.SANE + checkAliceSig
                    + Ansi.YELLOW + "\nAlice's certificate verified: " + Ansi.SANE + checkAliceCert
                    + Ansi.YELLOW + "\nAlice's DH parameters verified: " + Ansi.SANE + checkAliceDHParams);

            if (!checkAliceSig || !checkAliceDHParams || !checkAliceCert) {
                System.exit(1);
            }

            step++;

            out.println("\n\n" + Ansi.MAGENTA + step + ")"
                    + Ansi.CYAN + " Alice encrypts with the Common Secret Key, using AES in CBC mode with PKCS#5 Padding, a message then encodes it and sends it to Bob..."
                    + Ansi.SANE);

            byte[] m = EncryptionTool.Encrypt("This is ma big secret".getBytes(), aliceSecretKey, "AES/CBC/PKCS5Padding", true, security_provider);
            out.println(Ansi.GREEN + "\nAlice -> Bob: [encrypted message encoded]" + Ansi.SANE);

            step++;

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
