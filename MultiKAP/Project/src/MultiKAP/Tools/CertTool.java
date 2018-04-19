package MultiKAP.Tools;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * @author icsd12015 *
 */
//Περοιέχει μεθόδους για τη χρηση πιστοποιητικων
public class CertTool {

    //Ο αλγοριθμος για τη ψηφιακη υπογραφη της CA στα πιστοποιητικα
    private static final String signatureAlgorithm = "SHA1withRSA";

    //Τα δυο ASN1 identifier id's για τη προσθηκη των παραμέτρων του DiffieHellman στα πιστοποιητικα 
    public static final ASN1ObjectIdentifier OID_P = new ASN1ObjectIdentifier("1.2.0.1.5.1.1.1.6.2");
    public static final ASN1ObjectIdentifier OID_G = new ASN1ObjectIdentifier("1.1.1.6.2.1.2.0.1.5");
    public static final ASN1ObjectIdentifier OID_A = new ASN1ObjectIdentifier("1.2.0.1.5.1.1.1.6.2.1");
    public static final ASN1ObjectIdentifier OID_B = new ASN1ObjectIdentifier("1.1.1.6.2.1.2.0.1.5.2");

    //Μεθοδος για δημιουργια αιτηματος πιστοποιησης PKCS10CertificationRequest (Bouncy Castle)
    public static PKCS10CertificationRequest generateRequest (String name, PublicKey pk, AlgorithmParameterSpec dh,
                                                              X509Certificate CAcert, PrivateKey CAprivateKey,
                                                              Provider provider) throws IOException, OperatorCreationException {

        //Προσθηκη extensions στο πιστοποιητικο με το ονομα της οντοτητας και τους δυο πρωτους αριθμους του πρωτοκολου
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, name);
        X500Name subject = x500NameBld.build();
        DERSequence seq = null;
        ASN1ObjectIdentifier oid1 = null, oid2 = null;
        ASN1Integer value1 = null, value2 = null;
        if (dh instanceof DHParameterSpec) {
            oid1 = OID_G;
            oid2 = OID_P;
            value1 = new ASN1Integer(((DHParameterSpec) dh).getG());
            value2 = new ASN1Integer(((DHParameterSpec) dh).getP());
        }
        if (dh instanceof ECParameterSpec) {
            oid1 = OID_A;
            oid2 = OID_B;
            value1 = new ASN1Integer(((ECParameterSpec) dh).getCurve().getA().toBigInteger());
            value2 = new ASN1Integer(((ECParameterSpec) dh).getCurve().getB().toBigInteger());
        }
        seq = new DERSequence(new ASN1Encodable[]{oid1, value1});
        ArrayList<GeneralName> namesList = new ArrayList<>();
        namesList.add(new GeneralName(GeneralName.otherName, seq));
        GeneralNames altName1 = GeneralNames.getInstance(new DERSequence((GeneralName[]) namesList.toArray(new GeneralName[]{})));

        seq = new DERSequence(new ASN1Encodable[]{oid2, value2});
        namesList.clear();
        namesList.add(new GeneralName(GeneralName.otherName, seq));
        GeneralNames altName2 = GeneralNames.getInstance(new DERSequence((GeneralName[]) namesList.toArray(new GeneralName[]{})));

        //Δημιουργια του builder με τις παραμετρους και το δημοσιο κλειδι
        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pk);
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectKeyIdentifier, false, pk.getEncoded());
        extGen.addExtension(Extension.certificateIssuer, false, new X500Name(CAcert.getSubjectDN().getName()));
        //BasicConstraints false επειδη το πιστοποιητικο δεν ειναι ανθυπογραφο
        extGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        extGen.addExtension(oid1, false, altName1);
        extGen.addExtension(oid2, false, altName2);
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        //Δημιουργια και επιστροφη του αιτηματος πιστοποιησης
        return requestBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(CAprivateKey));
    }

    //Μεθοδος για δημιουργια πιστοποιητικου X.509 βαση ενος αιτηματος πιστοποιησης
    public static X509Certificate getCertificate (PKCS10CertificationRequest csr, X509Certificate CAcert, PrivateKey CAprivateKey, Provider provider) throws
            OperatorCreationException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

        //Παραμετροι πιστοποιητικου
        // το startDate απο την οποιο και μετα το πιστοποιητικο ειναι valid ειναι η τρεχουσα timestamp
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();

        //Tα στοιχεια του αιτηματος
        X500Name subject = csr.getSubject();

        //Δημιουργια SerialNumber βαση του τρεχων timestamp
        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis()); // <-- Using the current timestamp as the certificate serial number

        // το endDate απο την οποιο και μετα το πιστοποιητικο δεν ειναι valid ειναι 6 μηνες μετα
        calendar.add(Calendar.MONTH, 6);
        Date endDate = calendar.getTime();

        //Δημιουργια ContentSigner απο το private κλειδι της PassManager CA
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(CAprivateKey);

        //Κατασκευη του δημοσιου κλειδιου που περιεχει το αιτημα
        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
        RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(rsaSpec);

        //Δημιουργια builder με τις παραμετρους αυτες
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(CAcert.getSubjectDN().getName()),
                certSerialNumber,
                startDate,
                endDate,
                subject,
                publicKey
        );

        //Προσθηκη και των extensions που περιεχει το αιτημα στον builder
        org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
        for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                    Extension ext = extensions.getExtension(oid);
                    certBuilder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                }
            }
        }

        //Δημιουργια και επιστροφη του πιστοποιητικου του πιστοποιητικου με υπογραφη της CA
        return  new JcaX509CertificateConverter().setProvider(provider).getCertificate(certBuilder.build(contentSigner));
    }

    //Μεθοδος για δημιουργια ανθυπογραφου πιστοποιητικου
    public static X509Certificate getSelfSignedCertificate (KeyPair keyPair, String CAname, String teamNames, Provider provider) throws CertificateException, IOException, OperatorCreationException {
        //Παραμετροι πιστοποιητικου
        // το startDate απο την οποιο και μετα το πιστοποιητικο ειναι valid ειναι η τρεχουσα timestamp
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();

        //Προσθηκη Extensions με το ονομα της CA και τα στοιχεια των μελων της ομαδας
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, CAname);
        x500NameBld.addRDN(BCStyle.O, teamNames);
        X500Name subject = x500NameBld.build();

        //Δημιουργια SerialNumber βαση του τρεχων timestamp
        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis()); // <-- Using the current timestamp as the certificate serial number

        // το endDate απο την οποιο και μετα το πιστοποιητικο δεν ειναι valid ειναι 1 χρονος μετα
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        //Δημιουργια ContentSigner απο το private κλειδι του pair που δοθηκε (ο εαυτος της)
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        //Δημιουργια του builder με τις παραμετρους και το δημοσιο κλειδι
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                certSerialNumber,
                startDate,
                endDate,
                subject,
                keyPair.getPublic());

        //BasicConstraints true επειδη το πιστοποιητικο ειναι ανθυπογραφο
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        //Δημιουργια και επιστροφη του πιστοποιητικου (Bouncy Castle Provider)
        return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certBuilder.build(contentSigner));
    }

    //Επιστρεφει την τιμη ενος extension απο ενα πιστοποιητικο βαση του object identifier του extension
    public static String getExtensionValue (X509Certificate cert, ASN1ObjectIdentifier oid) {
        try {
            String asn1 = JcaX509ExtensionUtils.parseExtensionValue(cert.getExtensionValue(oid.toString())).toString();
            return asn1.substring(oid.toString().length() + 7, asn1.length() - 2);
        } catch (IOException ex) {
            return null;
        }
    }

}
