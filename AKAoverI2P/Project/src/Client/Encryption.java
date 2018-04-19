package Client;

//icsd12015 icsd11162 icsd11122

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;

//Αυτη η κλαση υλοποιει Συμμετρικη και Ασσυμετρη κρυπτογραφηση 
public class Encryption {

    public static String Encrypt(String plain, Key key, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherBytes = cipher.doFinal(plain.getBytes());

        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    public static String Decrypt(String encrypted, Key key, String algorithm) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        byte[] byteData;
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byteData = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(byteData);
    }

    //Μεθοδοι για την δημιουργια συμμετρικων κλειδιων
    public static Key getRandomKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        return keyGen.generateKey();
    }

    public static Key getRandomKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        if (keySize != 0) {
            keyGen.init(keySize);
        }
        return keyGen.generateKey();
    }

    public static Key generateKey(String algorithm, byte[] key) throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom(key);
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(sr);
        return keyGen.generateKey();
    }

    public static Key generateKey(String algorithm, int keySize, byte[] key) throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom(key);
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(sr);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    public static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    //Κατασκευη κλειδιου απο πινακα bytes
    public static Key getKeyFromBytes(byte[] data, String algorithm) {
        return new SecretKeySpec(data, algorithm);
    }

    //Αυτες οι μεθοδοι ειναι για κατασκευη των δημοσιων και ιδιωτικων κλειδιων 
    public static PublicKey constructPublicKey(String skey, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PublicKey publicKey = null;
        byte[] publicKeyBytes = Base64.getDecoder().decode(skey);
        publicKey = KeyFactory.getInstance(algorithm).generatePublic(
                new X509EncodedKeySpec(publicKeyBytes));
        return publicKey;
    }

    public static PrivateKey constructPrivateKey(String skey, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PrivateKey privateKey = null;
        byte[] privateKeyBytes = Base64.getDecoder().decode(skey);
        privateKey = KeyFactory.getInstance(algorithm).generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyBytes));
        return privateKey;
    }
    public static PublicKey constructX509PublicKey(String skey, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            IOException {
        byte[] sPublicKeyBytes = (new BASE64Decoder()).decodeBuffer(skey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(sPublicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey constructPKCS8PrivateKey(String skey, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            IOException {
        byte[] sPrivateKeyBytes = (new BASE64Decoder()).decodeBuffer(skey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(sPrivateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
