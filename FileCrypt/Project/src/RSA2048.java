import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

public class RSA2048 {
    //idiotiko kleidi efarmogis me kodikopoihsh Base64
    private final String PRIVATE_KEY_STRING = "MIICeQIBADANBgkqhkiG9w0BAQ"
            + "EFAASCAmMwggJfAgEAAoGBALpQA3T3+CTt04KtdFiYZt63K0sF4Mx8pd8k0v2Hok"
            + "HAcO/y0p+6Q62ZuvI8jciAU9pskeWHzseM0B1UeMwIkWZl68ErC7n06nIM9hGQdo"
            + "fIGvE6TTko3blwOzVm+73H/sUW6B+bZMGvnwOWh/2v9ZAjsmMARWPAyMLXTODcXI"
            + "kxAgMBAAECgYEAh05SpGDtkowxnmav5yOPGdG2nD6BmqAvqlXI8RzOpqfGnUwg0K"
            + "VqPyo1DXUSlvkzbJ6KekJd1qgaACL3s13JkXFF4Jq3eqQhaWBmEu5TM7ypR1SPH7"
            + "V7J4i/dFk+dya0yC53JAA0hPpclZpxGiu2b9UCFZNLFPZL92LkLOrYfg0CQQDoNZ"
            + "GAhYwQBpLZeDmuedfkY8UIePXTdCq7M/PEK31LvkJgNTrwRe3K+IJPrA+tmaQnaT"
            + "kID6i+Vw3laxhv6V43AkEAzWaoO3KkUGOMkwaiDkkTRHT/kt03lrHN5ZZjjkivQl"
            + "Q2pCKXLOfymzTWNkMQNUVOiC0HteMD5l4ehkGW8dhf1wJBANbnhNKqRhcqzkuf3d"
            + "pg/3Jq95ZAxFm/gDCjAy6BhUNNQQbjHLn0LgAUAB4WQqhKskabNmIEhAosbTru47"
            + "3m//8CQQCFpGKXc2sHxw3C59DvPIqlwv46/2ZYzU1rMSOLgy1NGeAHgV4dYLlQVN"
            + "t/qLjWAEctgScAKDn0XI69ydU9fAw3AkEA2VIaUn19FpI4OkUA6C29J0HEltbiDA"
            + "RFRLiJIVOwbXFTc3wjqdiPyRwWRYsHOCF0ApaywyeKVo3kBm1zhFLUTQ==";
    
    private final String KEY_FILEPATH = "Folders/AppKey";
    
    public RSA2048(){
        File keyDir = new File(KEY_FILEPATH);
        if(!keyDir.exists() && !keyDir.isDirectory()){
            keyDir.mkdir();
        }
    }
    
    public byte[] encrypt(String text) {
        byte[] cipherText = null;
        try {
            //pairnei to antikeimeno cipher gia ton algoruthmo RSA
            final Cipher cipher = Cipher.getInstance("RSA");
            final PublicKey publicKey = getPublicKeyFromFile(KEY_FILEPATH);
            
            //Kwdikopoiei to keimeno me xrisi tou dimosiou kleidiou
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }
    
    public String decrypt(byte[] text) {
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            final PrivateKey privateKey = getPrivateKeyFromString(PRIVATE_KEY_STRING);
            
             //Apokwdikopoiei to keimeno me xrisi tou idiotikou kleidiou
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }
    //Pairnei to dimosio kleidi apo to arxeio
    private PublicKey getPublicKeyFromFile(String filepath){
        PublicKey key = null;
        try {
            ObjectInputStream inStream = new ObjectInputStream(new FileInputStream(filepath+"/public.key"));
            key = (PublicKey) inStream.readObject();
        } catch (IOException ex ) {
            Logger.getLogger(RSA2048.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(RSA2048.class.getName()).log(Level.SEVERE, null, ex);
        }
        return key;
    }
    //Metatrepei to kodikopoihmeno se Base64 keimeno tou idiotikou kleidiou pisw se kleidi
    private PrivateKey getPrivateKeyFromString(String keyString){
        PrivateKey key = null;
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        try { 
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSA2048.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(RSA2048.class.getName()).log(Level.SEVERE, null, ex);
        }
        return key;
    }
    //Me auton ton tropo dimiourgithikan ta kleidia
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      return keyGen.generateKeyPair();
  }

}
