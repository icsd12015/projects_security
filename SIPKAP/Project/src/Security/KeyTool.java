package Security;

import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author icsd12015 *
 */
//Περοιέχει μεθόδους για Δημιουργια και Ανακατασκευη Ασσυμτετρων και Συμμετρικων Κλειδιων
public class KeyTool {

    //Δημιουργια  κλειδιου για συμμετρικη κρυπτογραφια δεδομενου του  μεγεθους του κλειδιου σε bits, αλγοριθμου και του security provider
    public static SecretKey getRandomKey (int keySize, String algorithm, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, provider);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    //Κατασκευη κλειδιου για συμμετρικη κρυπτογραφια δεδομενου των bytes του κλειδιου και του αλγοριθμου
    public static SecretKey constructKey (String algorithm, byte[] K) {
        return new SecretKeySpec(K, algorithm);
    }

    //Κατασκευη κλειδιου για συμμετρικη κρυπτογραφια δεδομενου των bytes του κλειδιου, το μεγεθος σε bits και του αλγοριθμου
    public static SecretKey constructKey (String algorithm, int keySize, byte[] K) {
        return new SecretKeySpec(K, 0, keySize / 8, algorithm);
    }

    //Δημιουργια ζευγους κλειδιων για ασυμμετρη κρυπτογραφια δεδομενου τις παραμετρους του αλγοριθμου, τον αλγοριθμο και του security provider
    public static KeyPair generateKeyPair (String algorithm, AlgorithmParameterSpec params, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException,
                                                                                                                      InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, provider);
        keyGen.initialize(params);
        return keyGen.generateKeyPair();
    }

    //Δημιουργια ζευγους κλειδιων για ασυμμετρη κρυπτογραφια δεδομενου το μεγεθος του κλειδιου σε bits, τον αλγοριθμο και του security provider
    public static KeyPair generateKeyPair (String algorithm, int keySize, Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, provider);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    //Κατασκευη δημοσιου κλειδιου για ασυμμετρη κρυπτογραφια δεδομενου των bytes του κλειδιου, του αλγοριθμο και του security provider
    public static PublicKey constructPublicKey (byte[] pkey, String algorithm, Provider provider) throws NoSuchAlgorithmException,
                                                                                                         InvalidKeySpecException,
                                                                                                         NoSuchProviderException {

        return KeyFactory.getInstance(algorithm, provider).generatePublic(new X509EncodedKeySpec(pkey));
    }

    //Κατασκευη ιδιωτικου κλειδιου για ασυμμετρη κρυπτογραφια δεδομενου των bytes του κλειδιου, του αλγοριθμο και του security provider
    public static PrivateKey constructPrivateKey (byte[] skey, String algorithm, Provider provider) throws NoSuchAlgorithmException,
                                                                                                           InvalidKeySpecException,
                                                                                                           NoSuchProviderException {
        return KeyFactory.getInstance(algorithm, provider).generatePrivate(new PKCS8EncodedKeySpec(skey));
    }

}
