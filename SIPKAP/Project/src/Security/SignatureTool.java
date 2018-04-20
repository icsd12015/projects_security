package Security;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
/**
 * @author icsd12015 *
 */
//Περιέχει μεθοδους για τη ψηφιακη υπογραφη δεδομενων και επιβεβαιωση ψηφιακων υπογραφων
public class SignatureTool {

    //Ο αλγοριθμος για τη ψηφιακη υπογραφη στα πιστοποιητικα
    public static final String algorithm = "SHA1withRSA";

    //Δημιουργια υπογραφης δεδομενων δεδομενου των δεδομενα, το κλειδι, το πιστοποιητικο, το πιστοποιητικο της Certificate Authority και του security provider
    public static byte[] sign (byte[] data, PrivateKey key, X509Certificate cert, X509Certificate certCA, Provider prov)
            throws NoSuchAlgorithmException, SignatureException, CertificateEncodingException, OperatorCreationException, CMSException, IOException, InvalidKeyException {

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        List certList = new ArrayList();
        certList.add(cert);
        certList.add(certCA);
        Store certs = new JcaCertStore(certList);
        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(prov).build(algorithm, key, cert));
        gen.addCertificates(certs);

        CMSTypedData cms = new CMSProcessableByteArray(data);

        CMSSignedData signed = gen.generate(cms); //,true

        return signed.getEncoded();
    }
    //Επιβεβαιωση υπογραφης δεδομενων δεδομενου των δεδομενων, της υπογραφης και του security provider
    public static boolean verify (byte[] data, byte[] signature, Provider prov) throws CMSException, CertificateException, OperatorCreationException {
        CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(data), signature);
        SignerInformationStore signers = cms.getSignerInfos();

        Iterator it = signers.getSigners().iterator();

        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertificateHolder certHolder = (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).toArray()[0];
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(prov).getCertificate(certHolder);

            try {
                if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(prov).build(cert))) {
                    return false;
                }
            } catch (CMSSignerDigestMismatchException e) {
                return false;
            }
        }
        return true;
    }
    //Ανακτηση πιστοποιητικου απο μια ψηγιακη υπογραφη
    public static X509Certificate getCertificate (byte[] signature, Provider prov) throws CMSException, CertificateException {
        CMSSignedData cms = new CMSSignedData(signature);
        SignerInformation signer = (SignerInformation) cms.getSignerInfos().getSigners().toArray()[0];
        X509CertificateHolder certHolder = (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).toArray()[0];
        return new JcaX509CertificateConverter().setProvider(prov).getCertificate(certHolder);
    }
}
